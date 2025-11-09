import SwiftUI
import Combine
import CoreData
import LocalAuthentication
import OSLog

// MARK: - Configuration
/// Enterprise configuration for PrivateEye module
struct PrivateEyeConfiguration {
    /// Authentication levels for the Private Eye system
    enum AuthenticationLevel: String, Codable, CaseIterable {
        case standard = "Standard"
        case elevated = "Elevated"
        case restricted = "Restricted"
        case classified = "Classified"
    }
    
    /// Session timeout in seconds
    var sessionTimeout: TimeInterval = 300
    
    /// Authentication level required
    var requiredAuthLevel: AuthenticationLevel = .standard
    
    /// Whether to enable audit logging
    var enableAuditLogging: Bool = true
    
    /// Whether to force enterprise MDM policies
    var enforceMDMPolicies: Bool = true
    
    /// Whether to encrypt cached data
    var encryptCache: Bool = true
    
    /// Whether to require network security validation
    var validateNetworkSecurity: Bool = true
    
    /// Custom enterprise theme
    var theme: PrivateEyeTheme = .enterprise
}

// MARK: - Theme
/// Enterprise theming system for PrivateEye
struct PrivateEyeTheme {
    var primaryColor: Color
    var secondaryColor: Color
    var accentColor: Color
    var backgroundColor: Color
    var textColor: Color
    var fontFamily: String
    var cornerRadius: CGFloat
    var shadowRadius: CGFloat
    
    static let enterprise = PrivateEyeTheme(
        primaryColor: Color(red: 0.0, green: 0.29, blue: 0.59),
        secondaryColor: Color(red: 0.11, green: 0.38, blue: 0.63),
        accentColor: Color(red: 0.0, green: 0.47, blue: 0.75),
        backgroundColor: Color(red: 0.95, green: 0.95, blue: 0.97),
        textColor: Color(red: 0.13, green: 0.13, blue: 0.13),
        fontFamily: "SFProDisplay-Regular",
        cornerRadius: 8.0,
        shadowRadius: 4.0
    )
    
    static let secure = PrivateEyeTheme(
        primaryColor: Color(red: 0.2, green: 0.2, blue: 0.2),
        secondaryColor: Color(red: 0.3, green: 0.3, blue: 0.3),
        accentColor: Color(red: 0.7, green: 0.0, blue: 0.0),
        backgroundColor: Color(red: 0.1, green: 0.1, blue: 0.1),
        textColor: Color.white,
        fontFamily: "SFProDisplay-Medium",
        cornerRadius: 4.0,
        shadowRadius: 2.0
    )
}

// MARK: - Logging
/// Enterprise-grade logging system
class PrivateEyeLogger {
    private static let subsystem = "com.enterprise.privateeye"
    static let shared = PrivateEyeLogger()
    
    let appLogger: Logger
    let securityLogger: Logger
    let networkLogger: Logger
    let performanceLogger: Logger
    
    private init() {
        appLogger = Logger(subsystem: Self.subsystem, category: "application")
        securityLogger = Logger(subsystem: Self.subsystem, category: "security")
        networkLogger = Logger(subsystem: Self.subsystem, category: "network")
        performanceLogger = Logger(subsystem: Self.subsystem, category: "performance")
    }
    
    func logSecurityEvent(_ message: String, type: SecurityEventType, metadata: [String: String]? = nil) {
        securityLogger.info("\(type.rawValue): \(message) \(metadata ?? [:])")
        
        if type == .critical {
            // For critical events, also log to enterprise SIEM system
            sendToEnterpriseSIEM(event: message, type: type, metadata: metadata)
        }
    }
    
    enum SecurityEventType: String {
        case info = "INFO"
        case warning = "WARNING"
        case error = "ERROR"
        case critical = "CRITICAL"
    }
    
    private func sendToEnterpriseSIEM(event: String, type: SecurityEventType, metadata: [String: String]?) {
        // Implement enterprise SIEM integration here
        // This would typically send events to Splunk, ELK, or other enterprise monitoring systems
    }
}

// MARK: - Authentication
/// Enterprise authentication service
class PrivateEyeAuthenticationService: ObservableObject {
    static let shared = PrivateEyeAuthenticationService()
    
    @Published private(set) var isAuthenticated = false
    @Published private(set) var currentAuthLevel: PrivateEyeConfiguration.AuthenticationLevel = .standard
    
    private var sessionTimer: AnyCancellable?
    private let configuration: PrivateEyeConfiguration
    
    private init(configuration: PrivateEyeConfiguration = PrivateEyeConfiguration()) {
        self.configuration = configuration
    }
    
    func authenticate() async throws -> Bool {
        let context = LAContext()
        var error: NSError?
        
        // Check if biometric authentication is available
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            do {
                // Attempt biometric authentication
                let success = try await context.evaluatePolicy(
                    .deviceOwnerAuthenticationWithBiometrics,
                    localizedReason: "Authenticate to activate Private Eye Mode"
                )
                
                if success {
                    self.isAuthenticated = true
                    self.currentAuthLevel = .elevated
                    self.startSessionTimer()
                    
                    PrivateEyeLogger.shared.logSecurityEvent(
                        "User authenticated successfully with biometrics",
                        type: .info,
                        metadata: ["authLevel": currentAuthLevel.rawValue]
                    )
                    
                    return true
                }
            } catch {
                PrivateEyeLogger.shared.logSecurityEvent(
                    "Biometric authentication failed",
                    type: .warning,
                    metadata: ["error": error.localizedDescription]
                )
                throw PrivateEyeError.authenticationFailed
            }
        }
        
        // Fallback to enterprise SSO if biometrics unavailable
        return try await authenticateWithEnterpriseSSO()
    }
    
    private func authenticateWithEnterpriseSSO() async throws -> Bool {
        // Enterprise SSO implementation would go here
        // This is a placeholder for actual enterprise authentication logic
        
        // For demonstration, we'll simulate a successful authentication
        self.isAuthenticated = true
        self.currentAuthLevel = .standard
        self.startSessionTimer()
        
        PrivateEyeLogger.shared.logSecurityEvent(
            "User authenticated with Enterprise SSO",
            type: .info,
            metadata: ["authLevel": currentAuthLevel.rawValue]
        )
        
        return true
    }
    
    func elevatePrivileges() async throws -> Bool {
        // Implement enterprise privilege elevation logic
        // This typically requires additional authentication or approval
        
        PrivateEyeLogger.shared.logSecurityEvent(
            "User requested privilege elevation",
            type: .info,
            metadata: ["currentLevel": currentAuthLevel.rawValue, "requestedLevel": PrivateEyeConfiguration.AuthenticationLevel.restricted.rawValue]
        )
        
        // Simulate successful elevation
        self.currentAuthLevel = .restricted
        return true
    }
    
    func logout() {
        sessionTimer?.cancel()
        isAuthenticated = false
        currentAuthLevel = .standard
        
        PrivateEyeLogger.shared.logSecurityEvent(
            "User logged out",
            type: .info
        )
    }
    
    private func startSessionTimer() {
        sessionTimer?.cancel()
        
        sessionTimer = Timer.publish(every: configuration.sessionTimeout, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                self?.handleSessionTimeout()
            }
    }
    
    private func handleSessionTimeout() {
        logout()
        
        PrivateEyeLogger.shared.logSecurityEvent(
            "Session timed out due to inactivity",
            type: .info
        )
        
        // Notify user of session expiration
        NotificationCenter.default.post(name: .privateEyeSessionExpired, object: nil)
    }
}

// MARK: - Network Security
/// Enterprise network security validator
class NetworkSecurityValidator {
    static let shared = NetworkSecurityValidator()
    
    private init() {}
    
    func validateNetworkSecurity() -> Bool {
        // Check for enterprise VPN connection
        let vpnConnected = checkVPNConnection()
        
        // Check for certificate pinning
        let certificatesValid = validateCertificates()
        
        // Check for network traffic encryption
        let trafficEncrypted = validateTrafficEncryption()
        
        let result = vpnConnected && certificatesValid && trafficEncrypted
        
        PrivateEyeLogger.shared.logSecurityEvent(
            "Network security validation completed",
            type: result ? .info : .warning,
            metadata: [
                "vpnConnected": String(vpnConnected),
                "certificatesValid": String(certificatesValid),
                "trafficEncrypted": String(trafficEncrypted)
            ]
        )
        
        return result
    }
    
    private func checkVPNConnection() -> Bool {
        // Actual implementation would check if enterprise VPN is active
        return true
    }
    
    private func validateCertificates() -> Bool {
        // Actual implementation would validate certificate chain and pinning
        return true
    }
    
    private func validateTrafficEncryption() -> Bool {
        // Actual implementation would ensure traffic is properly encrypted
        return true
    }
}

// MARK: - MDM Compliance
/// Enterprise MDM policy validator
class MDMComplianceValidator {
    static let shared = MDMComplianceValidator()
    
    private init() {}
    
    func validateDeviceCompliance() -> Bool {
        // Check device encryption
        let deviceEncrypted = checkDeviceEncryption()
        
        // Check for jailbreak/rooting
        let deviceNotJailbroken = checkForJailbreak()
        
        // Check OS version compliance
        let osVersionCompliant = checkOSVersionCompliance()
        
        // Check required enterprise apps
        let requiredAppsInstalled = checkRequiredApps()
        
        let result = deviceEncrypted && deviceNotJailbroken && osVersionCompliant && requiredAppsInstalled
        
        PrivateEyeLogger.shared.logSecurityEvent(
            "MDM compliance validation completed",
            type: result ? .info : .warning,
            metadata: [
                "deviceEncrypted": String(deviceEncrypted),
                "deviceNotJailbroken": String(deviceNotJailbroken),
                "osVersionCompliant": String(osVersionCompliant),
                "requiredAppsInstalled": String(requiredAppsInstalled)
            ]
        )
        
        return result
    }
    
    private func checkDeviceEncryption() -> Bool {
        // Actual implementation would check if device encryption is enabled
        return true
    }
    
    private func checkForJailbreak() -> Bool {
        // Actual implementation would check for jailbreak/root indicators
        return true
    }
    
    private func checkOSVersionCompliance() -> Bool {
        // Actual implementation would validate OS is up to date per policy
        return true
    }
    
    private func checkRequiredApps() -> Bool {
        // Actual implementation would validate required enterprise apps are installed
        return true
    }
}

// MARK: - Data Access
/// Enterprise data access controller
class PrivateEyeDataController: ObservableObject {
    static let shared = PrivateEyeDataController()
    
    private let persistentContainer: NSPersistentContainer
    private let encryptionKey: Data?
    
    @Published private(set) var isDataLoaded = false
    
    private init() {
        persistentContainer = NSPersistentContainer(name: "PrivateEyeData")
        
        // Set up data encryption for container
        if let description = persistentContainer.persistentStoreDescriptions.first {
            description.setOption(true as NSNumber, forKey: NSPersistentStoreFileProtectionKey)
            description.shouldInferMappingModelAutomatically = true
            description.shouldMigrateStoreAutomatically = true
            
            // Enable encryption for the store
            encryptionKey = generateEncryptionKey()
            if let key = encryptionKey {
                description.setOption(key as NSObject, forKey: "NSPersistentStoreEncryptionKeyOption")
            }
        }
        
        loadPersistentStores()
    }
    
    private func generateEncryptionKey() -> Data? {
        // In a real implementation, this would use the Keychain to generate and store a secure key
        return "EnterpriseGradeEncryptionKey".data(using: .utf8)
    }
    
    private func loadPersistentStores() {
        persistentContainer.loadPersistentStores { [weak self] description, error in
            if let error = error {
                PrivateEyeLogger.shared.logSecurityEvent(
                    "Failed to load persistent stores",
                    type: .error,
                    metadata: ["error": error.localizedDescription]
                )
                return
            }
            
            self?.isDataLoaded = true
            PrivateEyeLogger.shared.appLogger.info("Persistent stores loaded successfully")
        }
    }
    
    func saveContext() {
        let context = persistentContainer.viewContext
        if context.hasChanges {
            do {
                try context.save()
                PrivateEyeLogger.shared.appLogger.info("Context saved successfully")
            } catch {
                PrivateEyeLogger.shared.logSecurityEvent(
                    "Failed to save context",
                    type: .error,
                    metadata: ["error": error.localizedDescription]
                )
            }
        }
    }
    
    var viewContext: NSManagedObjectContext {
        return persistentContainer.viewContext
    }
}

// MARK: - Errors
/// Enterprise error handling
enum PrivateEyeError: Error {
    case authenticationFailed
    case sessionExpired
    case insufficientPrivileges
    case networkSecurityViolation
    case mdmComplianceViolation
    case dataEncryptionFailure
    case auditLogFailure
    case genericError(String)
    
    var localizedDescription: String {
        switch self {
        case .authenticationFailed:
            return "Authentication failed. Please try again or contact IT support."
        case .sessionExpired:
            return "Your session has expired. Please authenticate again."
        case .insufficientPrivileges:
            return "You do not have sufficient privileges for this operation."
        case .networkSecurityViolation:
            return "Network security requirements not met. Please connect to secure network."
        case .mdmComplianceViolation:
            return "Device does not meet security requirements. Contact IT support."
        case .dataEncryptionFailure:
            return "Unable to encrypt sensitive data. Operation aborted."
        case .auditLogFailure:
            return "Failed to record audit log. Please report this issue."
        case .genericError(let message):
            return "Error: \(message)"
        }
    }
}

// MARK: - Activity Tracking
/// Enterprise activity tracking for compliance
class PrivateEyeActivityTracker {
    static let shared = PrivateEyeActivityTracker()
    
    private var activities: [Activity] = []
    private let dateFormatter: DateFormatter
    
    struct Activity {
        let timestamp: Date
        let action: String
        let user: String
        let metadata: [String: String]?
    }
    
    private init() {
        dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
    }
    
    func trackActivity(action: String, metadata: [String: String]? = nil) {
        let currentUser = UserDefaults.standard.string(for: .currentUserKey) ?? "unknown"
        let activity = Activity(
            timestamp: Date(),
            action: action,
            user: currentUser,
            metadata: metadata
        )
        
        activities.append(activity)
        
        // Log the activity
        PrivateEyeLogger.shared.appLogger.info(
            "\(action) by \(currentUser) at \(dateFormatter.string(from: activity.timestamp))"
        )
        
        // Send to enterprise monitoring if needed
        if action.contains("critical") || action.contains("security") {
            sendToEnterpriseMonitoring(activity: activity)
        }
        
        // Prune old activities to prevent memory issues
        if activities.count > 1000 {
            activities.removeFirst(500)
        }
    }
    
    func generateActivityReport() -> String {
        var report = "PRIVATE EYE ACTIVITY REPORT\n"
        report += "Generated: \(dateFormatter.string(from: Date()))\n\n"
        
        for activity in activities {
            report += "[\(dateFormatter.string(from: activity.timestamp))] \(activity.action) by \(activity.user)\n"
            if let metadata = activity.metadata, !metadata.isEmpty {
                report += "  Metadata: \(metadata)\n"
            }
        }
        
        return report
    }
    
    private func sendToEnterpriseMonitoring(activity: Activity) {
        // Implementation would connect to enterprise monitoring systems
        // This is a placeholder for actual enterprise monitoring integration
    }
}

// MARK: - Notifications
extension Notification.Name {
    static let privateEyeSessionExpired = Notification.Name("com.enterprise.privateeye.sessionExpired")
    static let privateEyeSecurityViolation = Notification.Name("com.enterprise.privateeye.securityViolation")
    static let privateEyeDataUpdated = Notification.Name("com.enterprise.privateeye.dataUpdated")
}

// MARK: - Extensions
extension UserDefaults {
    enum Key: String {
        case currentUserKey = "com.enterprise.privateeye.currentUser"
        case lastLoginTimestamp = "com.enterprise.privateeye.lastLogin"
        case securityPreferences = "com.enterprise.privateeye.securityPrefs"
    }
    
    func string(for key: Key) -> String? {
        return string(forKey: key.rawValue)
    }
    
    func set(_ value: String, for key: Key) {
        set(value, forKey: key.rawValue)
    }
    
    func date(for key: Key) -> Date? {
        return object(forKey: key.rawValue) as? Date
    }
    
    func set(_ value: Date, for key: Key) {
        set(value, forKey: key.rawValue)
    }
}

// MARK: - Metrics
/// Enterprise metrics tracking system
class PrivateEyeMetrics {
    static let shared = PrivateEyeMetrics()
    
    private var performanceMetrics = [String: TimeInterval]()
    private var securityMetrics = [String: Int]()
    private var usageMetrics = [String: Int]()
    
    private init() {}
    
    func trackPerformance(operation: String, duration: TimeInterval) {
        performanceMetrics[operation] = (performanceMetrics[operation] ?? 0) + duration
        
        PrivateEyeLogger.shared.performanceLogger.info(
            "Performance: \(operation) took \(duration) seconds"
        )
    }
    
    func trackSecurityEvent(event: String) {
        securityMetrics[event] = (securityMetrics[event] ?? 0) + 1
    }
    
    func trackUsage(feature: String) {
        usageMetrics[feature] = (usageMetrics[feature] ?? 0) + 1
    }
    
    func generateMetricsReport() -> String {
        var report = "PRIVATE EYE METRICS REPORT\n"
        report += "Generated: \(Date().formatted(date: .numeric, time: .standard))\n\n"
        
        report += "Performance Metrics:\n"
        for (operation, duration) in performanceMetrics.sorted(by: { $0.key < $1.key }) {
            report += "  - \(operation): \(String(format: "%.2f", duration))s\n"
        }
        
        report += "\nSecurity Metrics:\n"
        for (event, count) in securityMetrics.sorted(by: { $0.key < $1.key }) {
            report += "  - \(event): \(count) occurrences\n"
        }
        
        report += "\nUsage Metrics:\n"
        for (feature, count) in usageMetrics.sorted(by: { $0.key < $1.key }) {
            report += "  - \(feature): \(count) uses\n"
        }
        
        return report
    }
    
    func reportToEnterpriseAnalytics() {
        // In a real implementation, this would send metrics to enterprise analytics systems
        // such as Splunk, AppDynamics, Datadog, etc.
    }
}

// MARK: - Secure Storage
/// Enterprise secure storage system
class SecureStorageManager {
    static let shared = SecureStorageManager()
    
    private init() {}
    
    func storeSecureData(_ data: Data, forKey key: String) throws {
        // In a real implementation, this would use the iOS Keychain with proper
        // access control and protection levels
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Track metrics
        let startTime = Date()
        
        // This is a simplified version - real implementation would be more robust
        PrivateEyeLogger.shared.logSecurityEvent(
            "Storing secure data",
            type: .info,
            metadata: ["key": key]
        )
        
        // Track performance
        let duration = Date().timeIntervalSince(startTime)
        PrivateEyeMetrics.shared.trackPerformance(operation: "secureStorage.store", duration: duration)
    }
    
    func retrieveSecureData(forKey key: String) throws -> Data? {
        // In a real implementation, this would retrieve from iOS Keychain
        
        // Track metrics
        let startTime = Date()
        
        // This is a simplified version - real implementation would be more robust
        PrivateEyeLogger.shared.logSecurityEvent(
            "Retrieving secure data",
            type: .info,
            metadata: ["key": key]
        )
        
        // Track performance
        let duration = Date().timeIntervalSince(startTime)
        PrivateEyeMetrics.shared.trackPerformance(operation: "secureStorage.retrieve", duration: duration)
        
        return nil
    }
    
    func deleteSecureData(forKey key: String) throws {
        // In a real implementation, this would delete from iOS Keychain
        
        PrivateEyeLogger.shared.logSecurityEvent(
            "Deleting secure data",
            type: .info,
            metadata: ["key": key]
        )
    }
}

// MARK: - Main View
/// Enterprise-grade Private Eye view with comprehensive security features
struct PrivateEyeView: View {
    @ObservedObject private var authService = PrivateEyeAuthenticationService.shared
    @ObservedObject private var dataController = PrivateEyeDataController.shared
    @State private var showingAuthenticationPrompt = false
    @State private var showingSecurityAlert = false
    @State private var alertMessage = ""
    @State private var isInitializing = true
    @State private var securityStatus: SecurityStatus = .initializing
    
    private let config = PrivateEyeConfiguration()
    private let theme = PrivateEyeTheme.enterprise
    
    enum SecurityStatus {
        case initializing
        case secure
        case warning
        case violation
    }
    
    var body: some View {
        ZStack {
            theme.backgroundColor
                .ignoresSafeArea()
            
            if isInitializing {
                VStack(spacing: 20) {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: theme.accentColor))
                        .scaleEffect(1.5)
                    
                    Text("Initializing Private Eye System...")
                        .font(.system(size: 18, weight: .medium, design: .default))
                        .foregroundColor(theme.textColor)
                }
            } else if !authService.isAuthenticated {
                authenticationView
            } else {
                mainContentView
            }
        }
        .onAppear {
            initializeSystem()
        }
        .alert(isPresented: $showingSecurityAlert) {
            Alert(
                title: Text("Security Alert"),
                message: Text(alertMessage),
                dismissButton: .default(Text("Acknowledge"))
            )
        }
        .onReceive(NotificationCenter.default.publisher(for: .privateEyeSessionExpired)) { _ in
            handleSessionExpiry()
        }
    }
    
    private var authenticationView: some View {
        VStack(spacing: 25) {
            Image(systemName: "eye.shield.fill")
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 80, height: 80)
                .foregroundColor(theme.primaryColor)
            
            Text("Private Eye Enterprise")
                .font(.system(size: 28, weight: .bold, design: .default))
                .foregroundColor(theme.primaryColor)
            
            Text("Secure Authentication Required")
                .font(.system(size: 18, weight: .medium, design: .default))
                .foregroundColor(theme.textColor)
            
            Button(action: {
                showingAuthenticationPrompt = true
                authenticate()
            }) {
                Text("Authenticate")
                    .font(.system(size: 18, weight: .semibold, design: .default))
                    .foregroundColor(.white)
                    .padding(.horizontal, 40)
                    .padding(.vertical, 12)
                    .background(theme.primaryColor)
                    .cornerRadius(theme.cornerRadius)
                    .shadow(radius: theme.shadowRadius / 2)
            }
            .padding(.top, 15)
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: theme.cornerRadius)
                .fill(Color.white)
                .shadow(radius: theme.shadowRadius)
        )
        .padding()
    }
    
    private var mainContentView: some View {
        VStack(spacing: 20) {
            HStack {
                Text("Private Eye")
                    .font(.system(size: 24, weight: .bold, design: .default))
                    .foregroundColor(theme.primaryColor)
                
                Spacer()
                
                Button(action: {
                    authService.logout()
                }) {
                    Text("Logout")
                        .font(.system(size: 16, weight: .medium, design: .default))
                        .foregroundColor(.white)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 8)
                        .background(theme.secondaryColor)
                        .cornerRadius(theme.cornerRadius)
                }
            }
            .padding(.horizontal)
            
            HStack {
                statusBadge
                
                Spacer()
                
                Text("Auth Level: \(authService.currentAuthLevel.rawValue)")
                    .font(.system(size: 14, weight: .medium, design: .default))
                    .foregroundColor(theme.textColor.opacity(0.8))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.gray.opacity(0.1))
                    .cornerRadius(theme.cornerRadius / 2)
            }
            .padding(.horizontal)
            
            Divider()
                .padding(.horizontal)
            
            VStack(alignment: .leading, spacing: 15) {
                Text("Active Security Measures")
                    .font(.system(size: 18, weight: .semibold, design: .default))
                    .foregroundColor(theme.textColor)
                
                SecurityFeatureRow(
                    icon: "lock.shield",
                    title: "Data Encryption",
                    isActive: true,
                    theme: theme
                )
                
                SecurityFeatureRow(
                    icon: "network",
                    title: "Secure Connection",
                    isActive: true,
                    theme: theme
                )
                
                SecurityFeatureRow(
                    icon: "person.badge.shield.checkmark",
                    title: "Identity Verification",
                    isActive: true,
                    theme: theme
                )
                
                SecurityFeatureRow(
                    icon: "doc.text.magnifyingglass",
                    title: "Activity Monitoring",
                    isActive: true,
                    theme: theme
                )
            }
            .padding()
            .background(
                RoundedRectangle(cornerRadius: theme.cornerRadius)
                    .fill(Color.white)
                    .shadow(radius: theme.shadowRadius / 2)
            )
            .padding(.horizontal)
            
            Spacer()
            
            HStack {
                Button(action: {
                    generateReport()
                }) {
                    Label("Generate Report", systemImage: "doc.text")
                        .font(.system(size: 16, weight: .medium, design: .default))
                        .foregroundColor(theme.primaryColor)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        .background(Color.white)
                        .cornerRadius(theme.cornerRadius)
                        .shadow(radius: theme.shadowRadius / 2)
                }
                
                Spacer()
                
                Button(action: {
                    Task {
                        await elevatePrivileges()
                    }
                }) {
                    Label("Elevate Privileges", systemImage: "arrow.up.shield")
                        .font(.system(size: 16, weight: .medium, design: .default))
                        .foregroundColor(.white)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        .background(theme.accentColor)
                        .cornerRadius(theme.cornerRadius)
                        .shadow(radius: theme.shadowRadius / 2)
                }
            }
            .padding(.horizontal)
            .padding(.bottom)
        }
        .background(theme.backgroundColor)
        .onAppear {
            PrivateEyeActivityTracker.shared.trackActivity(
                action: "Entered Private Eye Mode",
                metadata: ["authLevel": authService.currentAuthLevel.rawValue]
            )
        }
    }
    
    private var statusBadge: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(statusColor)
                .frame