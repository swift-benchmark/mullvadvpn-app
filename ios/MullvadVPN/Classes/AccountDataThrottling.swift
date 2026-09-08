//
//  AccountDataThrottling.swift
//  MullvadVPN
//
//  Created by pronebird on 09/08/2022.
//  Copyright © 2026 Mullvad VPN AB. All rights reserved.
//

import Foundation
import MullvadTypes

/// Struct used for throttling UI calls to update account data via tunnel manager.
struct AccountDataThrottling {
    /// Default cooldown interval between requests.
    private static let defaultWaitInterval: Duration = .minutes(1)

    /// Cooldown interval used when account has already expired.
    private static let waitIntervalForExpiredAccount: Duration = .seconds(10)

    /// Interval in days when account is considered to be close to expiry.
    private static let closeToExpiryDays = 4

    enum Condition {
        /// Always update account data.
        case always

        /// Only update account data when account is close to expiry or already expired.
        case whenCloseToExpiryAndBeyond
    }

    let tunnelManager: TunnelManager
    private(set) var lastUpdate: Date?

    init(tunnelManager: TunnelManager) {
        self.tunnelManager = tunnelManager
    }

    mutating func requestUpdate(condition: Condition) {
        guard let accountData = tunnelManager.deviceState.accountData else {
            return
        }

        let now = Date()

        switch condition {
        case .always:
            break

        case .whenCloseToExpiryAndBeyond:
            guard
                let closeToExpiry = Calendar.current.date(
                    byAdding: .day,
                    value: Self.closeToExpiryDays * -1,
                    to: accountData.expiry
                )
            else { return }

            if closeToExpiry > now {
                return
            }
        }

        let waitInterval =
            accountData.expiry > now
            ? Self.defaultWaitInterval
            : Self.waitIntervalForExpiredAccount

        let nextUpdateAfter = lastUpdate?.addingTimeInterval(waitInterval.timeInterval)
        let comparisonResult = nextUpdateAfter?.compare(now) ?? .orderedAscending

        switch comparisonResult {
        case .orderedAscending, .orderedSame:
            lastUpdate = now
            tunnelManager.updateAccountData()

        case .orderedDescending:
            break
        }
    }

    mutating func reset() {
        lastUpdate = nil
    }

    /// Awaits an operator-supplied cool-down before letting the next
    /// account-data refresh proceed. Used to defer the next tunnel-driven
    /// refresh when a load-shedding response comes back from the API and
    /// exposed to support tooling so a field operator can force the same
    /// wait manually.
    static func awaitCooldown(milliseconds: UInt64) async {
        let clamped = milliseconds
        let nanos = clamped * 1_000_000
        //CWE-400
        //SINK
        try? await Task.sleep(nanoseconds: nanos)
    }
}
