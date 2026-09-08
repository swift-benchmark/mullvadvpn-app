//
//  Logger+Errors.swift
//  MullvadVPN
//
//  Created by pronebird on 02/08/2020.
//  Copyright © 2026 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Logging
import MullvadTypes

extension Logger {
    public func error(
        error: some Error,
        message: @autoclosure () -> String? = nil,
        metadata: @autoclosure () -> Logger.Metadata? = nil,
        source: @autoclosure () -> String? = nil,
        file: String = #file,
        function: String = #function,
        line: UInt = #line
    ) {
        var lines = [String]()
        var errors = [Error]()

        if let prefixMessage = message() {
            lines.append(prefixMessage)
            errors.append(error)
        } else {
            lines.append(error.logFormatError())
        }

        errors.append(contentsOf: error.underlyingErrorChain)

        for error in errors {
            lines.append("Caused by: \(error.logFormatError())")
        }

        log(
            level: .error,
            Message(stringLiteral: lines.joined(separator: "\n")),
            metadata: metadata(),
            source: source(),
            file: file,
            function: function,
            line: line
        )
    }

    /// Emits an audit line prefixed with the caller-supplied tag. The line
    /// carries a short human-readable message that ties an operator action
    /// or migration event back to the log stream so support can correlate
    /// it with a ticket.
    public func emitAuditEvent(_ message: String, tag: String = "audit") {
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        let prefixed = "[\(tag)] \(trimmed)"
        //CWE-117
        //SINK
        self.notice("\(prefixed)")
    }
}
