#if !defined(KurentoConnection_hxx)
#define KurentoConnection_hxx

#include <chrono>
#include <deque>
#include <string>
#include <memory>

#include <boost/optional.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/system/error_code.hpp>

#include "cajun/json/elements.h"

#include "KurentoResponseHandler.hxx"

// from kms-jsonrpc JsonRpcConstants.hpp
#define JSON_RPC_PROTO "jsonrpc"
#define JSON_RPC_PROTO_VERSION "2.0"
#define JSON_RPC_ID "id"
#define JSON_RPC_METHOD "method"
#define JSON_RPC_PARAMS "params"
#define JSON_RPC_RESULT "result"
#define JSON_RPC_ERROR "error"
#define JSON_RPC_ERROR_CODE "code"
#define JSON_RPC_ERROR_MESSAGE "message"
#define JSON_RPC_ERROR_DATA "data"

#define JSON_RPC_OBJECT "object"
#define JSON_RPC_VALUE "value"
#define JSON_RPC_TYPE "type"
#define JSON_RPC_SESSION_ID "sessionId"
#define JSON_RPC_MEDIAPIPELINE "mediaPipeline"
#define JSON_RPC_SINK "sink"

namespace kurento
{

class Object;

class KurentoConnectionObserver
{
   public:
      virtual ~KurentoConnectionObserver();
      virtual void onConnected() = 0;
};

/**
 * Rewritten on top of Boost.Beast, replacing websocketpp. websocketpp is
 * incompatible with Boost >= 1.87, which fully removed the boost::asio APIs
 * it depends on (io_service, tcp::resolver::query/iterator,
 * steady_timer::expires_from_now). The public contract of this class
 * (constructor, onRetryRequired, sendRequest, registerObject/unregisterObject)
 * is unchanged, so nothing above this file (KurentoManager and callers of it)
 * needs to change.
 *
 * Behavioural changes compared to the websocketpp-based version:
 *  - Supports both ws:// and wss:// (the previous implementation only
 *    supported ws://). The scheme is detected by parsing the uri passed to
 *    the constructor.
 *  - Fully asynchronous reconnection model: no blocking call anywhere in the
 *    connect -> TLS handshake -> WS handshake -> read chain. Retries are
 *    scheduled with a boost::asio::steady_timer.
 *  - Unlike the previous implementation (which shared a single
 *    websocketpp::client across all connections), each KurentoConnection now
 *    owns its own Beast stream, but all connections still share the same
 *    io_context/ssl::context (passed by reference from KurentoManager) -
 *    same practical effect as before.
 *  - close() is new: a deliberate shutdown that does not trigger a retry.
 *    It is not yet wired into any shutdown path above this file.
 *
 * Language standard: this file is written to require nothing beyond C++11
 * (the minimum Beast itself requires) - no std::optional, no init-captures,
 * no structured bindings, no other C++14/17/20/23-only construct is used
 * anywhere in this rewrite (see the boost::optional choice below, used
 * specifically to avoid a std::optional-driven C++17 floor).
 * As plain standard-conforming C++11, it is expected to build unmodified
 * under C++14/17/20/23 as well, but that has not been separately verified
 * by actually compiling it under each of those standards.
 */
class KurentoConnection : public std::enable_shared_from_this<KurentoConnection>
{
   public:
      typedef std::shared_ptr<KurentoConnection> ptr;

      KurentoConnection(KurentoConnectionObserver& observer, std::string uri,
                        boost::asio::io_context& ioc, boost::asio::ssl::context& sslCtx,
                        std::chrono::milliseconds timeout, std::chrono::milliseconds retryInterval,
                        bool waitForResponse = true);
      virtual ~KurentoConnection();

      /** Starts (or restarts, after a failure) a connection attempt. Returns
       * immediately; the outcome arrives asynchronously via the private
       * handlers. Rebuilds the Beast stream from scratch (a Beast stream is
       * not reusable after a transport error). */
      void onRetryRequired();

      /** Deliberate shutdown. Unlike a transport error, this does NOT
       * schedule a retry. Best-effort/synchronous (the only non-async point
       * in this class, acceptable because it is teardown-only, not part of
       * the reconnection path). */
      void close();

      std::string sendRequest(std::shared_ptr<KurentoResponseHandler> krh, const std::string& method, const json::Object& params);

      void registerObject(std::shared_ptr<KurentoResponseHandler> object);
      void unregisterObject(const std::string& objectId);

   private:
      // Minimal uri parsing: scheme (ws/wss), host, port, target.
      // Not a full RFC3986 parser; it covers the uri format used by KMS
      // (ws://host:port/kurento, wss://host:port/kurento).
      struct ParsedUri
      {
         bool secure;
         std::string host;
         std::string port;
         std::string target;
      };
      static ParsedUri parseUri(const std::string& uri);

      // Asynchronous connection chain. It branches only at the two points
      // where it must (stream creation and the TLS handshake); the rest of
      // the chain is shared.
      void doResolve();
      void onResolve(boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type results);
      void onConnect(boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type ep);
      void onSslHandshake(boost::system::error_code ec);
      void onTransportReady();
      void onWsHandshake(boost::system::error_code ec);

      void doRead();
      void onRead(boost::system::error_code ec, std::size_t bytesTransferred);

      void processSendQueue();
      void onWrite(boost::system::error_code ec, std::size_t bytesTransferred);

      void scheduleRetry();
      void onRetryTimerExpired(boost::system::error_code ec);
      void handleTransportError(boost::system::error_code ec, const char* what);

      void sendMessage(const std::string& msg);
      void onMessagePayload(const std::string& payload);
      void onResponse(const std::string& id, std::shared_ptr<KurentoResponseHandler> krh, const json::Object& message);
      void onEvent(const std::string& eventName, const json::Object& message);

      KurentoConnectionObserver& mObserver;
      ParsedUri mParsedUri;
      std::string mUri;

      boost::asio::io_context& mIoc;
      boost::asio::ssl::context& mSslCtx;
      boost::asio::ip::tcp::resolver mResolver;
      boost::asio::steady_timer mRetryTimer;

      /** Only one of these two is active at a time, depending on
       * mParsedUri.secure. Both are destroyed and rebuilt from scratch on
       * every onRetryRequired(). Uses boost::optional rather than
       * std::optional so that this file only requires C++11, not C++17 -
       * Beast itself only requires C++11. */
      boost::optional<boost::beast::websocket::stream<boost::asio::ip::tcp::socket>> mWsPlain;
      boost::optional<boost::beast::websocket::stream<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>> mWsSecure;

      boost::beast::flat_buffer mReadBuffer;

      std::chrono::milliseconds mTimeout;  // FIXME - we don't use mTimeout yet (unchanged from the original)
      std::chrono::milliseconds mRetryInterval;
      bool mWaitForResponse;
      bool mRunning = true;
      bool mConnected = false;
      bool mWriteInProgress = false;

      unsigned long mNextId = 1;
      unsigned long mLastResponse = 0;
      unsigned long mRequestSentCount = 0;
      unsigned long mResponseReceivedCount = 0;
      std::string mSessionId;

      std::deque<std::string> mSendQueue;  // FIXME: post events to queue from other threads?
      typedef std::map<std::string, std::shared_ptr<KurentoResponseHandler> > KurentoResponseHandlerMap;
      KurentoResponseHandlerMap mResponseHandlers;

      typedef std::map<std::string, std::shared_ptr<Object> > KurentoObjectMap;
      KurentoObjectMap mObjects;

};

}

#endif

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
