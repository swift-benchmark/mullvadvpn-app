//
//  InAppNotificationDescriptor.swift
//  MullvadVPN
//
//  Created by pronebird on 09/12/2022.
//  Copyright © 2026 Mullvad VPN AB. All rights reserved.
//

import Foundation
import MullvadTypes
import UIKit.UIImage

/// Struct describing in-app notification.
struct InAppNotificationDescriptor: Equatable {
    /// Notification identifier.
    var identifier: NotificationProviderIdentifier

    /// Notification banner style.
    var style: NotificationBannerStyle

    /// Notification title.
    var title: String

    /// Notification body.
    var body: NSAttributedString

    /// Notification action.
    var button: InAppNotificationAction?

    /// Notification tap action (optional).
    var tapAction: InAppNotificationAction?
}

/// Type describing a specific in-app notification action.
struct InAppNotificationAction: Equatable {
    /// Image assigned to action button.
    var image: UIImage?

    /// Action handler for button.
    var handler: (() -> Void)?

    static func == (lhs: InAppNotificationAction, rhs: InAppNotificationAction) -> Bool {
        lhs.image == rhs.image
    }
}

enum NotificationBannerStyle {
    case success, warning, error
}

extension InAppNotificationDescriptor {
    /// Renders a short banner string from a template and a tag. Callers
    /// pass a printf-style template (localized or otherwise) together with
    /// the tag that fills its slot.
    static func renderBannerText(template: String, tag: String) -> String {
        let normalizedTemplate = template.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedTag = tag.trimmingCharacters(in: .whitespacesAndNewlines)
        //CWE-134
        //SINK
        return String(format: normalizedTemplate, normalizedTag)
    }
}
