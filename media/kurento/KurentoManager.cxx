
#include <boost/asio/ssl/context.hpp>

#include "rutil/Logger.hxx"

#include "KurentoManager.hxx"
#include "KurentoConnection.hxx"
#include "KurentoSubsystem.hxx"

namespace ssl = boost::asio::ssl;

using namespace kurento;

#define RESIPROCATE_SUBSYSTEM kurento::KurentoSubsystem::KURENTOCLIENT

KurentoManager::KurentoManager(std::chrono::milliseconds timeout, std::chrono::milliseconds retryInterval)
   : mTimeout(timeout),
     mRetryInterval(retryInterval),
     mSslCtx(ssl::context::tls_client)
{
   // Certificate verification is enabled by default (verify_peer + the
   // system's default CA paths). If the target KMS uses a self-signed
   // certificate (common in test/development deployments), the caller needs
   // to decide explicitly what to do:
   //   - load its CA explicitly: mSslCtx.load_verify_file("ca.pem");
   //   - or relax this to ssl::verify_none.
   // Neither is done here by default, to avoid silently weakening security.
   mSslCtx.set_verify_mode(ssl::verify_peer);
   mSslCtx.set_default_verify_paths();
}

KurentoManager::~KurentoManager()
{

}

void
KurentoManager::process()
{
   mIoc.poll();
}

KurentoConnection::ptr
KurentoManager::getKurentoConnection(const std::string& uri, KurentoConnectionObserver& observer)
{
   KurentoConnection::ptr kConnection = std::make_shared<KurentoConnection>(observer, uri, mIoc, mSslCtx, mTimeout, mRetryInterval);

   // This map was previously declared but never populated (dead code). It
   // is now populated here; this costs nothing and avoids connections being
   // referenced only from outside this class. It does not change any
   // observable behaviour.
   mConnections[uri] = kConnection;

   // Note that connect here only requests a connection. No network messages are
   // exchanged until the event loop starts running (KurentoManager::process(),
   // which the caller is expected to invoke regularly) and drains the pending
   // operations on mIoc.
   kConnection->onRetryRequired();

   return kConnection;

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
