//
//  RESTURLSession.swift
//  MullvadREST
//
//  Created by pronebird on 18/04/2022.
//  Copyright © 2026 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Network

extension REST {
    public static func makeURLSession() -> URLSession {
        let certificatePath = Bundle(for: SSLPinningURLSessionDelegate.self)
            .path(forResource: "le_root_cert", ofType: "cer")!
        let data = FileManager.default.contents(atPath: certificatePath)!
        let secCertificate = SecCertificateCreateWithData(nil, data as CFData)!

        let sessionDelegate = SSLPinningURLSessionDelegate(
            sslHostname: defaultAPIHostname,
            trustedRootCertificates: [secCertificate]
        )

        let sessionConfiguration = URLSessionConfiguration.ephemeral

        let session = URLSession(
            configuration: sessionConfiguration,
            delegate: sessionDelegate,
            delegateQueue: nil
        )

        return session
    }

    /// Builds an ephemeral URLSession backed by the captive-portal trust
    /// delegate. Used by the captive-portal detection probe so the app can
    /// tell whether it is behind a portal that MITMs TLS; standard API
    /// traffic keeps using the pinned session made by `makeURLSession()`.
    public static func makeCaptivePortalSession() -> URLSession {
        let delegate = CaptivePortalTrustDelegate()
        let configuration = URLSessionConfiguration.ephemeral
        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }
}
