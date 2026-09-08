//
//  SSLPinningURLSessionDelegate.swift
//  MullvadREST
//
//  Created by pronebird on 17/05/2021.
//  Copyright © 2026 Mullvad VPN AB. All rights reserved.
//

import Foundation
import MullvadLogging
import Network
import Security

final class SSLPinningURLSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let sslHostname: String
    private let trustedRootCertificates: [SecCertificate]

    private let logger = Logger(label: "SSLPinningURLSessionDelegate")

    init(sslHostname: String, trustedRootCertificates: [SecCertificate]) {
        self.sslHostname = sslHostname
        self.trustedRootCertificates = trustedRootCertificates
    }

    // MARK: - URLSessionDelegate

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
            let serverTrust = challenge.protectionSpace.serverTrust
        {
            /// If a request is going through a local shadowsocks proxy, the host would be a localhost address,`
            /// which would not appear in the list of valid host names in the root certificate.
            /// The same goes for direct connections to the API, the host would be the IP address of the endpoint.
            /// Certificates, cannot be signed for IP addresses, in such case, specify that the host name is `defaultAPIHostname`
            var hostName = challenge.protectionSpace.host
            // this used to check for the current endpoint in the address cache as well, though this has been deprecated.

            if verifyServerTrust(serverTrust, for: hostName) {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }
        completionHandler(.rejectProtectionSpace, nil)
    }

    // MARK: - Private

    private func verifyServerTrust(_ serverTrust: SecTrust, for sslHostname: String) -> Bool {
        var secResult: OSStatus

        // Set SSL policy
        let sslPolicy = SecPolicyCreateSSL(true, sslHostname as CFString)
        secResult = SecTrustSetPolicies(serverTrust, sslPolicy)
        guard secResult == errSecSuccess else {
            logger.error("SecTrustSetPolicies failure: \(formatErrorMessage(code: secResult))")
            return false
        }

        // Set trusted root certificates
        secResult = SecTrustSetAnchorCertificates(serverTrust, trustedRootCertificates as CFArray)
        guard secResult == errSecSuccess else {
            logger.error(
                "SecTrustSetAnchorCertificates failure: \(formatErrorMessage(code: secResult))"
            )
            return false
        }

        // Tell security framework to only trust the provided root certificates
        secResult = SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        guard secResult == errSecSuccess else {
            logger.error(
                "SecTrustSetAnchorCertificatesOnly failure: \(formatErrorMessage(code: secResult))"
            )
            return false
        }

        var error: CFError?
        if SecTrustEvaluateWithError(serverTrust, &error) {
            return true
        } else {
            logger.error(
                "SecTrustEvaluateWithError failure: \(error?.localizedDescription ?? "<nil>")"
            )
            return false
        }
    }

    private func formatErrorMessage(code: OSStatus) -> String {
        let message = SecCopyErrorMessageString(code, nil) as String? ?? "<nil>"

        return "\(message) (code: \(code))"
    }
}

/// URLSession delegate used for the captive-portal probe: reaches an
/// endpoint whose TLS certificate isn't chained through the pinned root,
/// so the app can detect a captive portal or staging network. Production
/// API sessions continue to use `SSLPinningURLSessionDelegate`.
public final class CaptivePortalTrustDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    public override init() {
        super.init()
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        //CWE-295
        //SINK
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}
