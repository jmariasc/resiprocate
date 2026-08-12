
#include <openssl/ssl.h>

#include <boost/asio/connect.hpp>
#include <boost/beast/core/buffers_to_string.hpp>

#include "cajun/json/writer.h"

#include "rutil/Logger.hxx"
#include "rutil/Subsystem.hxx"

#include "KurentoConnection.hxx"
#include "KurentoSubsystem.hxx"
#include "Object.hxx"

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace websocket = boost::beast::websocket;
using tcp = boost::asio::ip::tcp;

using namespace kurento;
using namespace resip;

#define RESIPROCATE_SUBSYSTEM kurento::KurentoSubsystem::KURENTOCLIENT

//#define PING_MSG "{\"id\":\"1\",\"method\":\"ping\",\"params\":{\"interval\":240000},\"jsonrpc\":\"2.0\"}"

KurentoConnectionObserver::~KurentoConnectionObserver()
{
}

//-----------------------------------------------------------------------------
KurentoConnection::ParsedUri
KurentoConnection::parseUri(const std::string& uri)
{
   ParsedUri result;
   std::string rest = uri;

   if (rest.rfind("wss://", 0) == 0)
   {
      result.secure = true;
      rest = rest.substr(6);
   }
   else if (rest.rfind("ws://", 0) == 0)
   {
      result.secure = false;
      rest = rest.substr(5);
   }
   else
   {
      // No explicit scheme: default to non-secure, matching the behaviour of
      // the previous websocketpp::client<asio_client>-based implementation
      // (which only ever spoke ws://).
      result.secure = false;
   }

   const std::string::size_type slashPos = rest.find('/');
   const std::string hostPort = (slashPos == std::string::npos) ? rest : rest.substr(0, slashPos);
   result.target = (slashPos == std::string::npos) ? "/" : rest.substr(slashPos);

   const std::string::size_type colonPos = hostPort.find(':');
   if (colonPos == std::string::npos)
   {
      result.host = hostPort;
      result.port = result.secure ? "443" : "80";
   }
   else
   {
      result.host = hostPort.substr(0, colonPos);
      result.port = hostPort.substr(colonPos + 1);
   }

   return result;
}
//-----------------------------------------------------------------------------
KurentoConnection::KurentoConnection(KurentoConnectionObserver& observer, std::string uri,
                                     net::io_context& ioc, ssl::context& sslCtx,
                                     std::chrono::milliseconds timeout, std::chrono::milliseconds retryInterval,
                                     bool waitForResponse)
   : mObserver(observer),
     mParsedUri(parseUri(uri)),
     mUri(uri),
     mIoc(ioc),
     mSslCtx(sslCtx),
     mResolver(ioc),
     mRetryTimer(ioc),
     mTimeout(timeout),  // FIXME - we don't use mTimeout yet
     mRetryInterval(retryInterval),
     mWaitForResponse(waitForResponse)
{
}
//-----------------------------------------------------------------------------
KurentoConnection::~KurentoConnection()
{
   // FIXME (unchanged from the original: no explicit shutdown is performed
   // here; see close() for a deliberate shutdown, which callers may want to
   // invoke from their own teardown path)
}
//-----------------------------------------------------------------------------
void
KurentoConnection::onRetryRequired()
{
   InfoLog(<<"trying to open connection to Kurento: " << mUri);

   mWsPlain  = boost::none;
   mWsSecure = boost::none;
   mConnected     = false;
   mWriteInProgress = false;

   // boost::optional::emplace() constructs the stream directly inside the
   // optional's storage (no copy/move of the stream is required).
   if (mParsedUri.secure)
   {
      mWsSecure.emplace(mIoc, mSslCtx);

      // SNI - required for many TLS servers (including reverse proxies in
      // front of KMS) to serve the correct certificate.
      if (!SSL_set_tlsext_host_name(mWsSecure->next_layer().native_handle(), mParsedUri.host.c_str()))
      {
         boost::system::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
         ErrLog(<<"failed to set SNI hostname: " << ec.message());
      }
   }
   else
   {
      mWsPlain.emplace(mIoc);
   }

   doResolve();
}
//-----------------------------------------------------------------------------
void
KurentoConnection::doResolve()
{
   auto self = shared_from_this();
   mResolver.async_resolve(mParsedUri.host, mParsedUri.port,
      [self](boost::system::error_code ec, tcp::resolver::results_type results)
      {
         self->onResolve(ec, results);
      });
}
//-----------------------------------------------------------------------------
void
KurentoConnection::onResolve(boost::system::error_code ec, tcp::resolver::results_type results)
{
   if (ec)
   {
      handleTransportError(ec, "resolve");
      return;
   }

   auto self = shared_from_this();
   auto onConnectCb = [self](boost::system::error_code ec2, tcp::resolver::results_type::endpoint_type ep)
   {
      self->onConnect(ec2, ep);
   };

   if (mParsedUri.secure)
      net::async_connect(mWsSecure->next_layer().next_layer(), results, onConnectCb);
   else
      net::async_connect(mWsPlain->next_layer(), results, onConnectCb);
}
//-----------------------------------------------------------------------------
void
KurentoConnection::onConnect(boost::system::error_code ec, tcp::resolver::results_type::endpoint_type ep)
{
   if (ec)
   {
      handleTransportError(ec, "connect");
      return;
   }

   if (mParsedUri.secure)
   {
      auto self = shared_from_this();
      mWsSecure->next_layer().async_handshake(ssl::stream_base::client,
         [self](boost::system::error_code ec2) { self->onSslHandshake(ec2); });
   }
   else
   {
      onTransportReady();
   }
}
//-----------------------------------------------------------------------------
void
KurentoConnection::onSslHandshake(boost::system::error_code ec)
{
   if (ec)
   {
      handleTransportError(ec, "TLS handshake");
      return;
   }
   onTransportReady();
}
//-----------------------------------------------------------------------------
void
KurentoConnection::onTransportReady()
{
   auto self = shared_from_this();
   auto cb = [self](boost::system::error_code ec) { self->onWsHandshake(ec); };

   if (mParsedUri.secure)
      mWsSecure->async_handshake(mParsedUri.host, mParsedUri.target, cb);
   else
      mWsPlain->async_handshake(mParsedUri.host, mParsedUri.target, cb);
}
//-----------------------------------------------------------------------------
void
KurentoConnection::onWsHandshake(boost::system::error_code ec)
{
   if (ec)
   {
      handleTransportError(ec, "websocket handshake");
      return;
   }

   InfoLog(<<"onOpen");
   mConnected = true;
   mObserver.onConnected();
   doRead();
   processSendQueue();
}
//-----------------------------------------------------------------------------
void
KurentoConnection::doRead()
{
   auto self = shared_from_this();
   auto cb = [self](boost::system::error_code ec, std::size_t n) { self->onRead(ec, n); };

   if (mParsedUri.secure)
      mWsSecure->async_read(mReadBuffer, cb);
   else
      mWsPlain->async_read(mReadBuffer, cb);
}
//-----------------------------------------------------------------------------
void
KurentoConnection::onRead(boost::system::error_code ec, std::size_t bytesTransferred)
{
   if (ec)
   {
      handleTransportError(ec, "read");
      return;
   }

   const bool isText = mParsedUri.secure ? mWsSecure->got_text() : mWsPlain->got_text();
   if (!isText)
   {
      ErrLog(<<"received unknown message type, ignoring it");
   }
   else
   {
      onMessagePayload(boost::beast::buffers_to_string(mReadBuffer.data()));
   }

   mReadBuffer.consume(mReadBuffer.size());

   if (mRunning)
      doRead();
}
//-----------------------------------------------------------------------------
void
KurentoConnection::onMessagePayload(const std::string& m)
{
   DebugLog(<<"received a message: " << m.c_str());

   json::Object message;
   std::stringstream stream;
   stream << m;
   try
   {
      json::Reader::Read(message, stream);
   }
   catch (json::Reader::ParseException& e)
   {
      // lines/offsets are zero-indexed, so bump them up by one for human presentation
      DebugLog(<<"Caught json::ParseException: " << e.what() << ", Line/offset: " << e.m_locTokenBegin.m_nLine + 1
               << '/' << e.m_locTokenBegin.m_nLineOffset + 1);
      return;
   }

   if(mSessionId.length() == 0)
   {
      if(message.Find(JSON_RPC_RESULT) != message.End())
      {
         json::Object& result = message[JSON_RPC_RESULT];
         if(result.Find(JSON_RPC_SESSION_ID) != result.End())
         {
            const json::String& sessionId = result[JSON_RPC_SESSION_ID];
            mSessionId = sessionId.Value();
            DebugLog(<<"registered new sessionId: " << mSessionId);
         }
      }
   }

   if(message.Find(JSON_RPC_ID) != message.End())
   {
      const json::String& idValue = message[JSON_RPC_ID];
      std::string id = idValue.Value();
      DebugLog(<<"has id = '" << id << "', response");

      const KurentoResponseHandlerMap::const_iterator it = mResponseHandlers.find(id);

      if(it != mResponseHandlers.end())
      {
         onResponse(id, it->second, message);
      }
      else
      {
         WarningLog(<<"unrecognised id = '" << id << "'");
      }

   }
   else
   {
      DebugLog(<<"has no id, checking if it is a notification");
      if(message.Find(JSON_RPC_METHOD) != message.End() && message[json::String(JSON_RPC_METHOD)] == json::String("onEvent"))
      {
         const json::String& eventName = message[JSON_RPC_PARAMS][JSON_RPC_VALUE][JSON_RPC_TYPE];
         const std::string& _eventName = eventName.Value();
         DebugLog(<<"received an event: " << _eventName);
         // the handler is probably in a different thread
         onEvent(_eventName, message);
      }
      else
      {
         DebugLog(<<"don't know how to handle the message: " << m);
      }
   }
}
//-----------------------------------------------------------------------------
void
KurentoConnection::onResponse(const std::string& id, std::shared_ptr<KurentoResponseHandler> krh, const json::Object& message)
{
   DebugLog(<<"id: " << id);
   unsigned long _id = std::stol(id);
   mResponseHandlers.erase(id);
   krh->processResponse(id, krh, message);
   if(_id > mLastResponse)
   {
      mLastResponse = _id;
   }
   else
   {
      WarningLog(<<"mLastResponse = " << mLastResponse << " but received response for earlier request: " << _id);
   }
   mResponseReceivedCount++;
   DebugLog(<< "mRequestSentCount = " << mRequestSentCount
            << " mResponseReceivedCount = " << mResponseReceivedCount);
   processSendQueue();
}
//-----------------------------------------------------------------------------
void
KurentoConnection::onEvent(const std::string& eventName, const json::Object& message)
{
   DebugLog(<<"event: " << eventName);

   const json::Object& values = message[JSON_RPC_PARAMS][JSON_RPC_VALUE];

   const json::String& objectId = values["object"];
   const std::string& _objectId = objectId.Value();

   if(mObjects.find(_objectId) != mObjects.end())
   {
      std::shared_ptr<Object> object = mObjects[_objectId];
      DebugLog(<<"event is being routed to Object " << _objectId);
      object->onEvent(eventName, message);
   }
   else
   {
      WarningLog(<<"event is for unknown Object " << _objectId);
   }

   // FIXME - does every event have an Object?
}
//-----------------------------------------------------------------------------
void
KurentoConnection::sendMessage(const std::string& msg)
{
   mSendQueue.push_back(msg);
   DebugLog(<< "mRequestSentCount = " << mRequestSentCount
            << " mResponseReceivedCount = " << mResponseReceivedCount);
   processSendQueue();
}
//-----------------------------------------------------------------------------
void
KurentoConnection::processSendQueue()
{
   if (!mConnected || mWriteInProgress || mSendQueue.empty())
      return;

   if(mWaitForResponse && mRequestSentCount > mResponseReceivedCount)
   {
      DebugLog(<<"new request to send but still waiting for response for a previous request");
      return;
   }

   const std::string msg = mSendQueue.front();
   mSendQueue.pop_front();

   mWriteInProgress = true;
   auto self = shared_from_this();
   auto cb = [self](boost::system::error_code ec, std::size_t n) { self->onWrite(ec, n); };

   if (mParsedUri.secure)
   {
      mWsSecure->text(true);
      mWsSecure->async_write(net::buffer(msg), cb);
   }
   else
   {
      mWsPlain->text(true);
      mWsPlain->async_write(net::buffer(msg), cb);
   }

   mRequestSentCount++;
   StackLog(<<"message sent to Kurento: " << msg);
}
//-----------------------------------------------------------------------------
void
KurentoConnection::onWrite(boost::system::error_code ec, std::size_t bytesTransferred)
{
   mWriteInProgress = false;

   if (ec)
   {
      handleTransportError(ec, "write");
      return;
   }

   // Continue the queue if there are pending messages (at most one async
   // write in flight at a time - a Beast stream does not support concurrent
   // writes).
   processSendQueue();
}
//-----------------------------------------------------------------------------
void
KurentoConnection::handleTransportError(boost::system::error_code ec, const char* what)
{
   if (!mRunning)
      return; // a deliberate shutdown is in progress, see close()

   ErrLog(<<"transport error during " << what << ": " << ec.message() << ", will retry after "
          << mRetryInterval.count() << " ms");

   mConnected = false;
   scheduleRetry();
}
//-----------------------------------------------------------------------------
void
KurentoConnection::scheduleRetry()
{
   auto self = shared_from_this();
   mRetryTimer.expires_after(mRetryInterval);
   mRetryTimer.async_wait([self](boost::system::error_code ec) { self->onRetryTimerExpired(ec); });
}
//-----------------------------------------------------------------------------
void
KurentoConnection::onRetryTimerExpired(boost::system::error_code ec)
{
   if (ec == net::error::operation_aborted || !mRunning)
      return;

   onRetryRequired();
}
//-----------------------------------------------------------------------------
void
KurentoConnection::close()
{
   mRunning = false;
   mRetryTimer.cancel();

   boost::system::error_code ec;
   if (mParsedUri.secure && mWsSecure)
      mWsSecure->close(websocket::close_code::normal, ec);
   else if (mWsPlain)
      mWsPlain->close(websocket::close_code::normal, ec);
   // Best-effort close: any error is ignored if the transport was already down.
}
//-----------------------------------------------------------------------------
std::string
KurentoConnection::sendRequest(std::shared_ptr<KurentoResponseHandler> krh, const std::string& method, const json::Object& params)
{
   const std::string id = std::to_string(mNextId++);
   StackLog(<<"generated ID " << id);
   json::Object request;
   json::Object _params = params;
   if(mSessionId.length() > 0)
   {
      _params[JSON_RPC_SESSION_ID] = json::String(mSessionId);
   }

   request[JSON_RPC_ID] = json::String(id);
   request[JSON_RPC_METHOD] = json::String(method);
   request[JSON_RPC_PARAMS] = _params;
   request[JSON_RPC_PROTO] = json::String(JSON_RPC_PROTO_VERSION);

   std::stringstream stream;
   json::Writer::Write(request, stream);

   mResponseHandlers[id] = krh;
   StackLog(<<"added ResponseHandler for id '" << id << "', handler count: " << mResponseHandlers.size());

   sendMessage(stream.str());

   return id;
}
//-----------------------------------------------------------------------------
void
KurentoConnection::registerObject(std::shared_ptr<KurentoResponseHandler> object)
{
   std::shared_ptr<Object> _object = std::static_pointer_cast<Object>(object);
   mObjects[_object->getId()] = _object;
}
//-----------------------------------------------------------------------------
// FIXME - we don't call this method from anywhere
void
KurentoConnection::unregisterObject(const std::string& objectId)
{
   mObjects.erase(objectId);
}

/* ====================================================================

 Copyright (c) 2021, Software Freedom Institute https://softwarefreedom.institute
 Copyright (c) 2021, Daniel Pocock https://danielpocock.com
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are
 met:

 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

 3. Neither the name of Plantronics nor the names of its contributors
    may be used to endorse or promote products derived from this
    software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 ==================================================================== */
