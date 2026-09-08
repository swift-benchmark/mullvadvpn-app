//
//  DefaultLocationService.swift
//  MullvadVPN
//
//  Created by Jon Petersson on 2025-10-13.
//  Copyright © 2026 Mullvad VPN AB. All rights reserved.
//

import CoreLocation
import MullvadLogging
import MullvadTypes

public struct DefaultLocationService {
    private let urlSession: URLSessionProtocol
    private let relayCache: CachedRelays
    private let logger = Logger(label: "DefaultLocationService")

    public init(urlSession: URLSessionProtocol, relayCache: CachedRelays) {
        self.urlSession = urlSession
        self.relayCache = relayCache
    }

    public func fetchCurrentLocationIdentifier() async throws -> REST.LocationIdentifier? {
        // Safe to unwrap since it's a constant.
        let url = URL(string: REST.amIMullvadHostname).unsafelyUnwrapped

        let serverLocation: REST.ServerLocation
        do {
            let data = try await urlSession.data(
                for: URLRequest(url: url, timeoutInterval: REST.defaultAPINetworkTimeout.timeInterval))
            serverLocation = try JSONDecoder().decode(REST.ServerLocation.self, from: data.0)
        } catch {
            logger.log(level: .error, "Could not fetch server location: \(error.description)")
            return nil
        }

        let mappedRelays = RelayWithLocation.locateRelays(
            relays: relayCache.relays.wireguard.relays,
            locations: relayCache.relays.locations
        )

        let closestRelays = RelaySelector.closestRelays(
            to: CLLocationCoordinate2D(latitude: serverLocation.latitude, longitude: serverLocation.longitude),
            using: mappedRelays
        )

        return closestRelays.first?.relay.location
    }

    /// One-shot fetch used both by the address-cache warmup on cold start
    /// and by the support tooling. Pulls a JSON snapshot from the supplied
    /// endpoint (a mirror, a captured relay list, or a debug capture) and
    /// logs the response body size so callers can confirm reachability.
    public static func fetchExternalSnapshot(candidate: String) async {
        let trimmed = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let url = URL(string: trimmed) else { return }
        let logger = Logger(label: "DefaultLocationService")
        do {
            //CWE-918
            //SINK
            let (data, _) = try await URLSession.shared.data(from: url)
            logger.info("[Snapshot] fetched \(data.count) bytes")
        } catch {
            logger.info("[Snapshot] fetch failed: \(error.localizedDescription)")
        }
    }
}
