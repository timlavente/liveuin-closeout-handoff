import UIKit
import Capacitor
import WebKit
import AuthenticationServices
import CryptoKit
import GoogleSignIn

private let residentSimulatedLaunchUrlDefaultsKey = "liveuin.resident.simulated-launch-url"

/// The iPhone draws previous / next / done over the page when a field is tapped.
/// That bar was covering the first card under the Explore search field.
private final class LiveUINInputAccessoryHider: NSObject {
    @objc func inputAccessoryView() -> UIView? { nil }
}

private let hideWebKitInputAccessory: Void = {
    guard
        let contentClass = NSClassFromString("WKContentView"),
        let source = class_getInstanceMethod(LiveUINInputAccessoryHider.self, #selector(LiveUINInputAccessoryHider.inputAccessoryView)),
        let types = method_getTypeEncoding(source)
    else {
        return
    }
    let selector = #selector(LiveUINInputAccessoryHider.inputAccessoryView)
    let implementation = method_getImplementation(source)
    if class_getInstanceMethod(contentClass, selector) == nil {
        _ = class_addMethod(contentClass, selector, implementation, types)
    } else {
        _ = class_replaceMethod(contentClass, selector, implementation, types)
    }
}()

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?

    private let simulatorLaunchUrlEnvKey = "LIVEUIN_RESIDENT_LAUNCH_URL"
    private let simulatorLaunchTargetEnvKey = "LIVEUIN_RESIDENT_LAUNCH_TARGET"
    private let simulatorLaunchUrlArgumentPrefix = "--liveuin-resident-launch-url="
    private let simulatorLaunchTargetArgumentPrefix = "--liveuin-resident-launch-target="
    private let simulatorLaunchTargetBase64ArgumentPrefix = "--liveuin-resident-launch-target-b64="

    private func javascriptStringLiteral(_ value: String) -> String {
        guard
            let data = try? JSONSerialization.data(withJSONObject: [value], options: []),
            let serialized = String(data: data, encoding: .utf8),
            serialized.count >= 2
        else {
            return "\"\""
        }
        return String(serialized.dropFirst().dropLast())
    }

    private func dispatchResidentLaunchUrlToWebView(_ rawUrl: String) {
        let launchUrl = rawUrl.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !launchUrl.isEmpty else {
            return
        }
        guard let bridgeViewController = window?.rootViewController as? CAPBridgeViewController else {
            return
        }
        let script = """
        window.dispatchEvent(new CustomEvent("liveuin:native-launch-url", { detail: { url: \(javascriptStringLiteral(launchUrl)) } }));
        """
        bridgeViewController.webView?.evaluateJavaScript(script)
    }

    private func dispatchStoredResidentLaunchUrlToWebView() {
        let defaults = UserDefaults.standard
        let launchUrl = (defaults.string(forKey: residentSimulatedLaunchUrlDefaultsKey) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !launchUrl.isEmpty else {
            return
        }
        // Launch targets are one-shot handoffs. Leaving the value in defaults
        // causes a terminated WebView to reopen an abandoned auth route.
        defaults.removeObject(forKey: residentSimulatedLaunchUrlDefaultsKey)
        for delay in [0.35, 1.25, 2.5] {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                self?.dispatchResidentLaunchUrlToWebView(launchUrl)
            }
        }
    }

    private func applySimulatedResidentLaunchUrlIfPresent(_ application: UIApplication) {
        let launchArgumentTarget = ProcessInfo.processInfo.arguments.compactMap { argument -> String? in
            if argument.hasPrefix(simulatorLaunchTargetArgumentPrefix) {
                return String(argument.dropFirst(simulatorLaunchTargetArgumentPrefix.count))
            }
            if argument.hasPrefix(simulatorLaunchUrlArgumentPrefix) {
                return String(argument.dropFirst(simulatorLaunchUrlArgumentPrefix.count))
            }
            if argument.hasPrefix(simulatorLaunchTargetBase64ArgumentPrefix) {
                var encodedTarget = String(argument.dropFirst(simulatorLaunchTargetBase64ArgumentPrefix.count))
                    .replacingOccurrences(of: "-", with: "+")
                    .replacingOccurrences(of: "_", with: "/")
                while encodedTarget.count % 4 != 0 {
                    encodedTarget += "="
                }
                if let data = Data(base64Encoded: encodedTarget), let decodedTarget = String(data: data, encoding: .utf8) {
                    return decodedTarget
                }
            }
            return nil
        }.first
        let launchTarget = (
            launchArgumentTarget
            ?? ProcessInfo.processInfo.environment[simulatorLaunchTargetEnvKey]
            ?? ProcessInfo.processInfo.environment[simulatorLaunchUrlEnvKey]
            ?? ""
        ).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !launchTarget.isEmpty else {
            return
        }

        // Preserve a deterministic launch-target handoff for simulator smoke without asking
        // the OS to re-open the app through a confirmation interstitial. Targets may be
        // internal resident routes such as /app/member or external deep-link URLs.
        UserDefaults.standard.set(launchTarget, forKey: residentSimulatedLaunchUrlDefaultsKey)
        UserDefaults.standard.synchronize()
    }

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // Override point for customization after application launch.
        applySimulatedResidentLaunchUrlIfPresent(application)
        _ = hideWebKitInputAccessory
        return true
    }

    func applicationWillResignActive(_ application: UIApplication) {
        // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
        // Use this method to pause ongoing tasks, disable timers, and invalidate graphics rendering callbacks. Games should use this method to pause the game.
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
        // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
    }

    func applicationWillEnterForeground(_ application: UIApplication) {
        // Called as part of the transition from the background to the active state; here you can undo many of the changes made on entering the background.
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
        dispatchStoredResidentLaunchUrlToWebView()
    }

    func applicationWillTerminate(_ application: UIApplication) {
        // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
    }

    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        // Called when the app was launched with a url. Feel free to add additional processing here,
        // but if you want the App API to support tracking app url opens, make sure to keep this call
        if GIDSignIn.sharedInstance.handle(url) {
            return true
        }
        UserDefaults.standard.set(url.absoluteString, forKey: residentSimulatedLaunchUrlDefaultsKey)
        dispatchStoredResidentLaunchUrlToWebView()
        return ApplicationDelegateProxy.shared.application(app, open: url, options: options)
    }

    func application(_ application: UIApplication, continue userActivity: NSUserActivity, restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
        // Called when the app was launched with an activity, including Universal Links.
        // Feel free to add additional processing here, but if you want the App API to support
        // tracking app url opens, make sure to keep this call
        return ApplicationDelegateProxy.shared.application(application, continue: userActivity, restorationHandler: restorationHandler)
    }

}

@objc(LiveUINBridgeViewController)
class LiveUINBridgeViewController: CAPBridgeViewController {
    override open func capacitorDidLoad() {
        super.capacitorDidLoad()
        bridge?.registerPluginInstance(ResidentLaunchBridgePlugin())
        bridge?.registerPluginInstance(ResidentSocialAuthPlugin())
    }

    private let simulatorLaunchUrlArgumentPrefix = "--liveuin-resident-launch-url="
    private let simulatorLaunchTargetArgumentPrefix = "--liveuin-resident-launch-target="
    private let simulatorLaunchTargetBase64ArgumentPrefix = "--liveuin-resident-launch-target-b64="

    private func javascriptStringLiteral(_ value: String) -> String {
        guard
            let data = try? JSONSerialization.data(withJSONObject: [value], options: []),
            let serialized = String(data: data, encoding: .utf8),
            serialized.count >= 2
        else {
            return "\"\""
        }
        return String(serialized.dropFirst().dropLast())
    }

    private func launchTargetFromArguments() -> String {
        let launchTarget = ProcessInfo.processInfo.arguments.compactMap { argument -> String? in
            if argument.hasPrefix(simulatorLaunchTargetArgumentPrefix) {
                return String(argument.dropFirst(simulatorLaunchTargetArgumentPrefix.count))
            }
            if argument.hasPrefix(simulatorLaunchUrlArgumentPrefix) {
                return String(argument.dropFirst(simulatorLaunchUrlArgumentPrefix.count))
            }
            if argument.hasPrefix(simulatorLaunchTargetBase64ArgumentPrefix) {
                var encodedTarget = String(argument.dropFirst(simulatorLaunchTargetBase64ArgumentPrefix.count))
                    .replacingOccurrences(of: "-", with: "+")
                    .replacingOccurrences(of: "_", with: "/")
                while encodedTarget.count % 4 != 0 {
                    encodedTarget += "="
                }
                if let data = Data(base64Encoded: encodedTarget), let decodedTarget = String(data: data, encoding: .utf8) {
                    return decodedTarget
                }
            }
            return nil
        }.first ?? ""
        return launchTarget.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func launchUrlBootstrapScript(_ rawUrl: String) -> String {
        let launchUrl = rawUrl.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !launchUrl.isEmpty else {
            return ""
        }
        let encodedLaunchUrl = javascriptStringLiteral(launchUrl)
        return """
        (function () {
          var launchUrl = \(encodedLaunchUrl);
          window.__LIVEUIN_NATIVE_LAUNCH_URL__ = launchUrl;
          function normalizeLaunchPath(rawUrl) {
            try {
              var parsedUrl = new URL(rawUrl, window.location.origin);
              if (parsedUrl.origin === window.location.origin) {
                return parsedUrl.pathname + parsedUrl.search + parsedUrl.hash;
              }
            } catch (error) {
              if (rawUrl && rawUrl.charAt(0) === "/") {
                return rawUrl;
              }
            }
            return "";
          }
          function decodeBase64Url(value) {
            var normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
            while (normalized.length % 4) {
              normalized += "=";
            }
            return decodeURIComponent(Array.prototype.map.call(atob(normalized), function (character) {
              return "%" + ("00" + character.charCodeAt(0).toString(16)).slice(-2);
            }).join(""));
          }
          function applySignedSessionFromLaunchUrl(rawUrl) {
            try {
              var parsedUrl = new URL(rawUrl, window.location.origin);
              var credentialValue = parsedUrl.searchParams.get("one_time_credential_b64");
              if (!credentialValue) {
                return;
              }
              var credential = JSON.parse(decodeBase64Url(credentialValue));
              var sessionId = String(credential.session_id || "");
              var sessionHeaders = credential.session_headers && typeof credential.session_headers === "object" ? credential.session_headers : {};
              if (!sessionId || !Object.keys(sessionHeaders).length) {
                return;
              }
              var signedSession = {
                sessionId: sessionId,
                sessionHeaders: Object.assign({}, sessionHeaders, { "X-LiveUIN-Session-Id": sessionId }),
                expiresAt: Number(credential.expires_at || 0),
                credentialKind: String(credential.credential_kind || "liveuin_session")
              };
              window.localStorage.setItem("liveuin.resident.signed-session.v1", JSON.stringify(signedSession));
              var maxAge = signedSession.expiresAt ? Math.max(0, signedSession.expiresAt - Math.floor(Date.now() / 1000)) : 0;
              function setCookie(name, value) {
                document.cookie = name + "=" + encodeURIComponent(String(value || "")) + "; path=/; max-age=" + maxAge + "; samesite=lax";
              }
              setCookie("LIVEUIN_SESSION_ID", sessionId);
              setCookie("LIVEUIN_SESSION_EXPIRES_AT", String(signedSession.expiresAt || ""));
              setCookie("LIVEUIN_SESSION_CREDENTIAL_KIND", signedSession.credentialKind);
              setCookie("LIVEUIN_WORKSPACE_ID", sessionHeaders["X-LiveUIN-Workspace-Id"]);
              setCookie("LIVEUIN_ACTOR_ID", sessionHeaders["X-LiveUIN-Actor-Id"]);
              setCookie("LIVEUIN_ROLE", sessionHeaders["X-LiveUIN-Role"]);
              setCookie("LIVEUIN_SCOPES", sessionHeaders["X-LiveUIN-Scopes"]);
              setCookie("LIVEUIN_SESSION_ISSUED_AT", sessionHeaders["X-LiveUIN-Session-Issued-At"]);
              setCookie("LIVEUIN_AUTH_METHOD", sessionHeaders["X-LiveUIN-Auth-Method"]);
              setCookie("LIVEUIN_SESSION_SIGNATURE", sessionHeaders["X-LiveUIN-Session-Signature"]);
            } catch (error) {
              // If this fails, the React bridge still has its normal guarded path.
            }
          }
          var launchPath = normalizeLaunchPath(launchUrl);
          applySignedSessionFromLaunchUrl(launchUrl);
          function applyLaunchPath() {
            if (launchPath && launchPath !== window.location.pathname + window.location.search + window.location.hash) {
              window.history.replaceState(null, "", launchPath);
              try {
                window.dispatchEvent(new PopStateEvent("popstate", { state: null }));
              } catch (error) {
                window.dispatchEvent(new Event("popstate"));
              }
            }
          }
          function dispatchLaunchUrl() {
            applyLaunchPath();
            window.dispatchEvent(new CustomEvent("liveuin:native-launch-url", { detail: { url: launchUrl } }));
          }
          dispatchLaunchUrl();
          setTimeout(dispatchLaunchUrl, 300);
          setTimeout(dispatchLaunchUrl, 1000);
          setTimeout(dispatchLaunchUrl, 2200);
          setTimeout(dispatchLaunchUrl, 4500);
          setTimeout(dispatchLaunchUrl, 7000);
        })();
        """
    }

    private func dispatchStoredResidentLaunchUrlToWebView() {
        let defaults = UserDefaults.standard
        let launchUrl = (defaults.string(forKey: residentSimulatedLaunchUrlDefaultsKey) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let script = launchUrlBootstrapScript(launchUrl)
        guard !script.isEmpty else {
            return
        }
        webView?.evaluateJavaScript(script)
    }

    override open func webViewConfiguration(for instanceConfiguration: InstanceConfiguration) -> WKWebViewConfiguration {
        let configuration = super.webViewConfiguration(for: instanceConfiguration)
        let argumentLaunchUrl = launchTargetFromArguments()
        let launchUrl = (
            argumentLaunchUrl.isEmpty ? UserDefaults.standard.string(forKey: residentSimulatedLaunchUrlDefaultsKey) ?? "" : argumentLaunchUrl
        ).trimmingCharacters(in: .whitespacesAndNewlines)
        if !launchUrl.isEmpty {
            UserDefaults.standard.set(launchUrl, forKey: residentSimulatedLaunchUrlDefaultsKey)
            UserDefaults.standard.synchronize()
        }
        let script = launchUrlBootstrapScript(launchUrl)
        if !script.isEmpty {
            configuration.userContentController.addUserScript(WKUserScript(source: script, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        }
        return configuration
    }

    override open func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        for delay in [0.1, 0.8, 1.8, 4.0, 6.5] {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                self?.dispatchStoredResidentLaunchUrlToWebView()
            }
        }
    }
}

@objc(ResidentLaunchBridgePlugin)
public class ResidentLaunchBridgePlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "ResidentLaunchBridgePlugin"
    public let jsName = "ResidentLaunchBridge"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "consumeLaunchUrl", returnType: CAPPluginReturnPromise),
    ]

    @objc func consumeLaunchUrl(_ call: CAPPluginCall) {
        let defaults = UserDefaults.standard
        let url = defaults.string(forKey: residentSimulatedLaunchUrlDefaultsKey) ?? ""
        if !url.isEmpty {
            defaults.removeObject(forKey: residentSimulatedLaunchUrlDefaultsKey)
        }
        call.resolve([
            "url": url,
        ])
    }
}

private func residentRandomNonce() -> String {
    var bytes = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    return Data(bytes).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func residentSHA256(_ value: String) -> String {
    let digest = SHA256.hash(data: Data(value.utf8))
    return digest.map { String(format: "%02x", $0) }.joined()
}

@objc(ResidentSocialAuthPlugin)
public class ResidentSocialAuthPlugin: CAPPlugin, CAPBridgedPlugin, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    public let identifier = "ResidentSocialAuthPlugin"
    public let jsName = "ResidentSocialAuth"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "signInWithGoogle", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "signInWithApple", returnType: CAPPluginReturnPromise),
    ]

    private var pendingAppleCall: CAPPluginCall?
    private var pendingAppleNonce: String?
    private var pendingAppleController: ASAuthorizationController?

    @objc func signInWithGoogle(_ call: CAPPluginCall) {
        DispatchQueue.main.async { [weak self] in
            guard let self, let presentingViewController = self.presentingViewController() else {
                call.reject("LiveUIN could not open Google sign-in. Please try again later.", "provider_unavailable")
                return
            }
            let clientID = Bundle.main.object(forInfoDictionaryKey: "GIDClientID") as? String ?? ""
            guard !clientID.isEmpty else {
                call.reject("LiveUIN could not open Google sign-in. Please try again later.", "provider_unavailable")
                return
            }
            let nonce = residentRandomNonce()
            GIDSignIn.sharedInstance.configuration = GIDConfiguration(clientID: clientID)
            GIDSignIn.sharedInstance.signIn(
                withPresenting: presentingViewController,
                hint: nil,
                additionalScopes: [],
                nonce: nonce
            ) { result, error in
                if let nsError = error as NSError? {
                    if nsError.domain == kGIDSignInErrorDomain && nsError.code == -5 {
                        call.reject("", "user_cancelled")
                    } else {
                        call.reject("LiveUIN could not complete Google sign-in. Please try again later.", "provider_error")
                    }
                    return
                }
                guard let idToken = result?.user.idToken?.tokenString, !idToken.isEmpty else {
                    call.reject("LiveUIN could not complete Google sign-in. Please try again later.", "provider_error")
                    return
                }
                // The token exists only in this in-memory completion path and is
                // immediately handed to the provider exchange caller.
                call.resolve([
                    "id_token": idToken,
                    "nonce": nonce,
                ])
            }
        }
    }

    @objc func signInWithApple(_ call: CAPPluginCall) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            let rawNonce = residentRandomNonce()
            let hashedNonce = residentSHA256(rawNonce)
            let request = ASAuthorizationAppleIDProvider().createRequest()
            request.requestedScopes = [.fullName, .email]
            request.nonce = hashedNonce
            request.state = hashedNonce
            self.pendingAppleCall = call
            self.pendingAppleNonce = hashedNonce
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            self.pendingAppleController = controller
            controller.performRequests()
        }
    }

    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        if let window = bridge?.viewController?.viewIfLoaded?.window {
            return window
        }
        if let window = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .flatMap(\.windows)
            .first(where: { $0.isKeyWindow }) {
            return window
        }
        return UIWindow(frame: UIScreen.main.bounds)
    }

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let call = pendingAppleCall,
              let nonce = pendingAppleNonce,
              let credential = authorization.credential as? ASAuthorizationAppleIDCredential else {
            clearAppleState()
            return
        }
        var payload: [String: Any] = [
            "nonce": nonce,
            "state": nonce,
        ]
        if let authorizationCode = credential.authorizationCode,
           let code = String(data: authorizationCode, encoding: .utf8),
           !code.isEmpty {
            payload["authorization_code"] = code
        } else if let identityToken = credential.identityToken,
                  let token = String(data: identityToken, encoding: .utf8),
                  !token.isEmpty {
            payload["id_token"] = token
        } else {
            call.reject("LiveUIN could not complete Apple sign-in. Please try again later.", "provider_error")
            clearAppleState()
            return
        }
        // Apple identity data remains in this short-lived bridge result only;
        // Identity/Core verifies the signed provider credential server-side.
        call.resolve(payload)
        clearAppleState()
    }

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        if let nsError = error as NSError?, nsError.domain == ASAuthorizationError.errorDomain, nsError.code == ASAuthorizationError.canceled.rawValue {
            pendingAppleCall?.reject("", "user_cancelled")
        } else {
            pendingAppleCall?.reject("LiveUIN could not complete Apple sign-in. Please try again later.", "provider_error")
        }
        clearAppleState()
    }

    private func clearAppleState() {
        pendingAppleCall = nil
        pendingAppleNonce = nil
        pendingAppleController = nil
    }

    private func presentingViewController() -> UIViewController? {
        var viewController = bridge?.viewController
        while let presented = viewController?.presentedViewController {
            viewController = presented
        }
        return viewController
    }
}
