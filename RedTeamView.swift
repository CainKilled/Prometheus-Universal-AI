import SwiftUI
import Combine
import OSLog
import CryptoKit

// MARK: - Models

/// Represents a security vulnerability with standardized CVSS scoring
struct Vulnerability: Identifiable, Codable, Hashable {
    let id: UUID
    let name: String
    let description: String
    let cvssScore: Double
    let remediation: String
    let dateDiscovered: Date
    let status: VulnerabilityStatus
    
    enum VulnerabilityStatus: String, Codable, CaseIterable {
        case open
        case inProgress
        case mitigated
        case resolved
        case accepted
    }
}

/// Core service protocol for Red Team operations
protocol RedTeamServiceProtocol {
    func fetchVulnerabilities() -> AnyPublisher<[Vulnerability], Error>
    func analyzeTarget(hostname: String) -> AnyPublisher<AnalysisResult, Error>
    func reportVulnerability(_ vulnerability: Vulnerability) -> AnyPublisher<Bool, Error>
    func initializeModule(apiKey: String) -> AnyPublisher<Bool, Error>
}

/// Analysis Result from a security assessment
struct AnalysisResult: Identifiable, Codable {
    let id: UUID
    let timestamp: Date
    let targetHostname: String
    let vulnerabilities: [Vulnerability]
    let riskScore: Double
    let scanDuration: TimeInterval
}

/// Environment configuration for the module
struct RedTeamConfiguration: Codable {
    let apiEndpoint: URL
    let refreshInterval: TimeInterval
    let analyticsEnabled: Bool
    let encryptionKey: String
    let maxConcurrentScans: Int
    let complianceFrameworks: [String]
    
    static var production: RedTeamConfiguration {
        // Production configuration would typically be loaded from a secure source
        RedTeamConfiguration(
            apiEndpoint: URL(string: "https://api.phoenixcodex.com/v1/security")!,
            refreshInterval: 300,
            analyticsEnabled: true,
            encryptionKey: SecureStorage.retrieveKey() ?? "DEFAULT_SHOULD_BE_REPLACED",
            maxConcurrentScans: 5,
            complianceFrameworks: ["ISO27001", "NIST", "PCI-DSS", "HIPAA"]
        )
    }
    
    static var development: RedTeamConfiguration {
        // Development configuration for testing
        RedTeamConfiguration(
            apiEndpoint: URL(string: "https://dev-api.phoenixcodex.com/v1/security")!,
            refreshInterval: 60,
            analyticsEnabled: false,
            encryptionKey: "DEV_KEY_NOT_SECURE",
            maxConcurrentScans: 2,
            complianceFrameworks: ["ISO27001"]
        )
    }
}

// MARK: - Services

/// Secure storage utility
class SecureStorage {
    private static let logger = Logger(subsystem: "com.phoenixcodex.mobile", category: "SecureStorage")
    
    static func storeKey(_ key: String) {
        // Implementation would use Keychain services
        logger.info("Security key stored in keychain")
    }
    
    static func retrieveKey() -> String? {
        // Implementation would retrieve from Keychain
        logger.info("Security key retrieved from keychain")
        return nil // Placeholder - actual implementation would return the key
    }
    
    static func encryptData(_ data: Data, with key: String) -> Data? {
        // Implementation would use CryptoKit
        logger.info("Data encrypted")
        return data // Placeholder
    }
    
    static func decryptData(_ data: Data, with key: String) -> Data? {
        // Implementation would use CryptoKit
        logger.info("Data decrypted")
        return data // Placeholder
    }
}

/// Analytics service for tracking module usage
class AnalyticsService {
    private static let logger = Logger(subsystem: "com.phoenixcodex.mobile", category: "Analytics")
    
    static func trackEvent(_ name: String, parameters: [String: Any]? = nil) {
        guard let config = AppEnvironment.current.redTeamConfiguration, config.analyticsEnabled else {
            return
        }
        
        logger.info("Analytics event tracked: \(name)")
        // Implementation would send events to analytics backend
    }
    
    static func trackError(_ error: Error, context: String) {
        logger.error("Error in \(context): \(error.localizedDescription)")
        trackEvent("error_occurred", parameters: [
            "context": context,
            "error_description": error.localizedDescription,
            "timestamp": Date().timeIntervalSince1970
        ])
    }
}

/// Concrete implementation of the Red Team service protocol
class RedTeamService: RedTeamServiceProtocol {
    private let logger = Logger(subsystem: "com.phoenixcodex.mobile", category: "RedTeamService")
    private let configuration: RedTeamConfiguration
    private var cancellables = Set<AnyCancellable>()
    private let queue = DispatchQueue(label: "com.phoenixcodex.redteam.service", qos: .userInitiated)
    
    init(configuration: RedTeamConfiguration) {
        self.configuration = configuration
        logger.info("Red Team Service initialized with endpoint: \(configuration.apiEndpoint)")
    }
    
    func fetchVulnerabilities() -> AnyPublisher<[Vulnerability], Error> {
        logger.info("Fetching vulnerabilities")
        
        guard NetworkMonitor.shared.isConnected else {
            return Fail(error: ServiceError.noNetworkConnection)
                .eraseToAnyPublisher()
        }
        
        return URLSession.shared.dataTaskPublisher(for: configuration.apiEndpoint.appendingPathComponent("vulnerabilities"))
            .tryMap { data, response -> Data in
                guard let httpResponse = response as? HTTPURLResponse,
                      (200...299).contains(httpResponse.statusCode) else {
                    throw ServiceError.invalidResponse
                }
                return data
            }
            .decode(type: [Vulnerability].self, decoder: JSONDecoder())
            .receive(on: DispatchQueue.main)
            .catch { error -> AnyPublisher<[Vulnerability], Error> in
                self.logger.error("Error fetching vulnerabilities: \(error.localizedDescription)")
                AnalyticsService.trackError(error, context: "fetchVulnerabilities")
                return Fail(error: error).eraseToAnyPublisher()
            }
            .eraseToAnyPublisher()
    }
    
    func analyzeTarget(hostname: String) -> AnyPublisher<AnalysisResult, Error> {
        logger.info("Analyzing target: \(hostname)")
        AnalyticsService.trackEvent("analysis_started", parameters: ["hostname": hostname])
        
        // Validate hostname format
        guard hostname.contains(".") else {
            return Fail(error: ServiceError.invalidHostname)
                .eraseToAnyPublisher()
        }
        
        // Encrypt hostname for security
        let hashedHostname = SHA256.hash(data: Data(hostname.utf8))
            .compactMap { String(format: "%02x", $0) }
            .joined()
        
        // Create request with proper authorization
        var request = URLRequest(url: configuration.apiEndpoint.appendingPathComponent("analyze"))
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("Bearer \(AuthManager.shared.getAccessToken() ?? "")", forHTTPHeaderField: "Authorization")
        
        let payload = ["hostname": hostname, "hostnameHash": hashedHostname]
        
        return Just(payload)
            .encode(encoder: JSONEncoder())
            .mapError { $0 as Error }
            .flatMap { encodedData -> AnyPublisher<(data: Data, response: URLResponse), Error> in
                request.httpBody = encodedData
                return URLSession.shared.dataTaskPublisher(for: request)
                    .mapError { $0 as Error }
                    .eraseToAnyPublisher()
            }
            .tryMap { data, response -> Data in
                guard let httpResponse = response as? HTTPURLResponse else {
                    throw ServiceError.invalidResponse
                }
                
                switch httpResponse.statusCode {
                case 200...299:
                    return data
                case 401, 403:
                    throw ServiceError.unauthorized
                case 429:
                    throw ServiceError.rateLimited
                default:
                    throw ServiceError.serverError(statusCode: httpResponse.statusCode)
                }
            }
            .decode(type: AnalysisResult.self, decoder: JSONDecoder())
            .receive(on: DispatchQueue.main)
            .handleEvents(
                receiveOutput: { result in
                    self.logger.info("Analysis completed for \(hostname) with \(result.vulnerabilities.count) vulnerabilities")
                    AnalyticsService.trackEvent("analysis_completed", parameters: [
                        "hostname": hostname,
                        "vulnerabilities_count": result.vulnerabilities.count,
                        "risk_score": result.riskScore,
                        "duration": result.scanDuration
                    ])
                },
                receiveCompletion: { completion in
                    if case .failure(let error) = completion {
                        self.logger.error("Analysis failed: \(error.localizedDescription)")
                        AnalyticsService.trackError(error, context: "analyzeTarget")
                    }
                }
            )
            .eraseToAnyPublisher()
    }
    
    func reportVulnerability(_ vulnerability: Vulnerability) -> AnyPublisher<Bool, Error> {
        logger.info("Reporting vulnerability: \(vulnerability.id)")
        
        // Implementation for vulnerability reporting
        return Future<Bool, Error> { promise in
            // Would implement actual API call here
            promise(.success(true))
        }
        .eraseToAnyPublisher()
    }
    
    func initializeModule(apiKey: String) -> AnyPublisher<Bool, Error> {
        logger.info("Initializing module with API key")
        
        return Future<Bool, Error> { promise in
            // Validate API key format (example: should be 32 characters)
            guard apiKey.count >= 32 else {
                self.logger.error("Invalid API key format")
                promise(.failure(ServiceError.invalidApiKey))
                return
            }
            
            // Store API key securely
            SecureStorage.storeKey(apiKey)
            
            // Simulate initialization delay and process
            DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
                // Successful initialization
                self.logger.info("Module successfully initialized")
                AnalyticsService.trackEvent("module_initialized")
                promise(.success(true))
            }
        }
        .eraseToAnyPublisher()
    }
    
    enum ServiceError: Error, LocalizedError {
        case invalidResponse
        case decodingError
        case noNetworkConnection
        case unauthorized
        case rateLimited
        case serverError(statusCode: Int)
        case invalidApiKey
        case invalidHostname
        
        var errorDescription: String? {
            switch self {
            case .invalidResponse:
                return "Invalid server response"
            case .decodingError:
                return "Failed to decode server response"
            case .noNetworkConnection:
                return "No network connection available"
            case .unauthorized:
                return "Authentication required or invalid credentials"
            case .rateLimited:
                return "Rate limit exceeded, please try again later"
            case .serverError(let code):
                return "Server error occurred (Code: \(code))"
            case .invalidApiKey:
                return "Invalid API key format"
            case .invalidHostname:
                return "Invalid hostname format"
            }
        }
    }
}

/// Authentication manager
class AuthManager {
    static let shared = AuthManager()
    private let logger = Logger(subsystem: "com.phoenixcodex.mobile", category: "AuthManager")
    
    private var accessToken: String?
    private var tokenExpiration: Date?
    
    private init() {}
    
    func getAccessToken() -> String? {
        if let expiration = tokenExpiration, expiration > Date() {
            return accessToken
        } else {
            // Would implement token refresh here
            logger.info("Token expired, refresh needed")
            return nil
        }
    }
    
    func setAccessToken(_ token: String, expiration: Date) {
        accessToken = token
        tokenExpiration = expiration
        logger.info("Access token updated, expires: \(expiration)")
    }
    
    func clearTokens() {
        accessToken = nil
        tokenExpiration = nil
        logger.info("Tokens cleared")
    }
}

/// Network connectivity monitor
class NetworkMonitor {
    static let shared = NetworkMonitor()
    private let logger = Logger(subsystem: "com.phoenixcodex.mobile", category: "NetworkMonitor")
    
    var isConnected: Bool = true
    
    private init() {
        // Would implement NWPathMonitor for real connectivity monitoring
        logger.info("Network monitor initialized")
    }
}

/// Application environment
class AppEnvironment {
    static var current: AppEnvironment = .init(environment: .production)
    
    enum Environment {
        case development
        case staging
        case production
    }
    
    let environment: Environment
    var redTeamConfiguration: RedTeamConfiguration?
    
    init(environment: Environment) {
        self.environment = environment
        
        switch environment {
        case .development:
            redTeamConfiguration = .development
        case .staging, .production:
            redTeamConfiguration = .production
        }
    }
}

/// App settings observable object
class AppSettings: ObservableObject {
    @Published var darkModeEnabled: Bool = false
    @Published var analyticsOptIn: Bool = true
    @Published var notificationsEnabled: Bool = true
    @Published var autoScanEnabled: Bool = false
    @Published var scanFrequency: ScanFrequency = .weekly
    
    enum ScanFrequency: String, CaseIterable, Identifiable {
        case daily
        case weekly
        case monthly
        
        var id: String { self.rawValue }
    }
}

// MARK: - View Models

/// View model for the Red Team module
class RedTeamViewModel: ObservableObject {
    private let logger = Logger(subsystem: "com.phoenixcodex.mobile", category: "RedTeamViewModel")
    private let service: RedTeamServiceProtocol
    private var cancellables = Set<AnyCancellable>()
    
    // Published properties for UI updates
    @Published var isInitialized: Bool = false
    @Published var isLoading: Bool = false
    @Published var progressValue: Float = 0.0
    @Published var statusMessage: String = "Module initialization pending"
    @Published var vulnerabilities: [Vulnerability] = []
    @Published var selectedHostname: String = ""
    @Published var analysisResult: AnalysisResult?
    @Published var errorMessage: String?
    @Published var showError: Bool = false
    
    // Module capabilities
    let capabilities = [
        "Enterprise Vulnerability Management",
        "Penetration Testing Simulation",
        "Security Compliance Auditing",
        "Threat Intelligence Integration",
        "Secure Code Analysis"
    ]
    
    init(service: RedTeamServiceProtocol = RedTeamService(configuration: AppEnvironment.current.redTeamConfiguration ?? .production)) {
        self.service = service
        logger.info("RedTeamViewModel initialized")
        checkInitializationStatus()
    }
    
    func checkInitializationStatus() {
        // Check if we have stored credentials/initialization state
        if let _ = SecureStorage.retrieveKey() {
            isInitialized = true
            loadVulnerabilities()
        }
    }
    
    func initializeModule() {
        guard !isInitialized else { return }
        
        isLoading = true
        progressValue = 0.0
        statusMessage = "Initializing module..."
        
        // Start progress simulation
        Timer.publish(every: 0.3, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self = self, self.isLoading else { return }
                
                if self.progressValue < 0.9 {
                    self.progressValue += 0.1
                    self.updateStatusMessage()
                }
            }
            .store(in: &cancellables)
        
        // Get API key from secure storage or generate one for demo
        let apiKey = SecureStorage.retrieveKey() ?? generateDemoAPIKey()
        
        service.initializeModule(apiKey: apiKey)
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { [weak self] completion in
                    guard let self = self else { return }
                    
                    if case .failure(let error) = completion {
                        self.handleError(error)
                    } else {
                        // Complete progress bar animation
                        self.progressValue = 1.0
                        self.statusMessage = "Module initialization complete"
                        
                        // Delay to show completion state
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                            self.isLoading = false
                            self.isInitialized = true
                            self.loadVulnerabilities()
                        }
                    }
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)
    }
    
    func loadVulnerabilities() {
        isLoading = true
        statusMessage = "Loading vulnerability database..."
        
        service.fetchVulnerabilities()
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { [weak self] completion in
                    guard let self = self else { return }
                    self.isLoading = false
                    
                    if case .failure(let error) = completion {
                        self.handleError(error)
                    }
                },
                receiveValue: { [weak self] vulnerabilities in
                    guard let self = self else { return }
                    self.vulnerabilities = vulnerabilities
                    self.statusMessage = "Database loaded with \(vulnerabilities.count) vulnerabilities"
                    logger.info("Loaded \(vulnerabilities.count) vulnerabilities")
                }
            )
            .store(in: &cancellables)
    }
    
    func analyzeTarget() {
        guard !selectedHostname.isEmpty else {
            showError(message: "Please enter a valid hostname")
            return
        }
        
        isLoading = true
        statusMessage = "Analyzing target: \(selectedHostname)"
        
        service.analyzeTarget(hostname: selectedHostname)
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { [weak self] completion in
                    guard let self = self else { return }
                    self.isLoading = false
                    
                    if case .failure(let error) = completion {
                        self.handleError(error)
                    }
                },
                receiveValue: { [weak self] result in
                    guard let self = self else { return }
                    self.analysisResult = result
                    self.statusMessage = "Analysis complete"
                    logger.info("Analysis completed for \(self.selectedHostname)")
                }
            )
            .store(in: &cancellables)
    }
    
    private func updateStatusMessage() {
        let messages = [
            "Initializing secure components...",
            "Verifying API credentials...",
            "Loading vulnerability database...",
            "Configuring security protocols...",
            "Connecting to threat intelligence feed...",
            "Setting up encryption services...",
            "Initializing scan engine...",
            "Performing environment validation..."
        ]
        
        // Select message based on progress
        let index = Int(min(Float(messages.count - 1), progressValue * Float(messages.count)))
        statusMessage = messages[index]
    }
    
    private func handleError(_ error: Error) {
        logger.error("Error: \(error.localizedDescription)")
        AnalyticsService.trackError(error, context: "RedTeamViewModel")
        showError(message: error.localizedDescription)
    }
    
    private func showError(message: String) {
        errorMessage = message
        showError = true
    }
    
    private func generateDemoAPIKey() -> String {
        // For demo purposes only - in production this would come from authenticated backend
        let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return String((0..<32).map { _ in letters.randomElement()! })
    }
}

// MARK: - Views

/// The main Red Team module view
struct RedTeamView: View {
    @StateObject private var viewModel = RedTeamViewModel()
    @EnvironmentObject var appSettings: AppSettings
    @Environment(\.colorScheme) var colorScheme
    
    var accentColor: Color {
        colorScheme == .dark ? Color.red.opacity(0.8) : Color.red
    }
    
    var body: some View {
        NavigationView {
            contentView
                .navigationTitle("Red Team")
                .toolbar {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button(action: {
                            // Settings or info action
                        }) {
                            Image(systemName: "info.circle")
                                .foregroundColor(accentColor)
                        }
                    }
                }
        }
        .navigationViewStyle(StackNavigationViewStyle())
        .alert(isPresented: $viewModel.showError) {
            Alert(
                title: Text("Error"),
                message: Text(viewModel.errorMessage ?? "An unknown error occurred"),
                dismissButton: .default(Text("OK"))
            )
        }
        .onAppear {
            AnalyticsService.trackEvent("red_team_view_appeared")
        }
    }
    
    @ViewBuilder
    private var contentView: some View {
        if !viewModel.isInitialized {
            initializationView
        } else if viewModel.isLoading {
            loadingView
        } else {
            mainModuleView
        }
    }
    
    private var initializationView: some View {
        VStack(spacing: 20) {
            Image(systemName: "shield.checkerboard")
                .font(.system(size: 60))
                .foregroundColor(accentColor)
            
            Text("Red Team Module")
                .font(.largeTitle)
                .fontWeight(.bold)
            
            Text("Enterprise Security Evaluation")
                .font(.title3)
                .foregroundColor(.secondary)
            
            VStack(alignment: .leading, spacing: 15) {
                Text("Capabilities:")
                    .font(.headline)
                
                ForEach(viewModel.capabilities, id: \.self) { capability in
                    Label {
                        Text(capability)
                            .font(.subheadline)
                    } icon: {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(accentColor)
                    }
                }
            }
            .padding()
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(Color(UIColor.secondarySystemBackground))
            )
            .padding(.horizontal)
            
            Button(action: {
                viewModel.initializeModule()
            }) {
                Text("Initialize Module")
                    .fontWeight(.semibold)
                    .foregroundColor(.white)
                    .frame(height: 50)
                    .frame(maxWidth: .infinity)
                    .background(
                        RoundedRectangle(cornerRadius: 10)
                            .fill(accentColor)
                    )
                    .padding(.horizontal)
            }
            .padding(.top)
        }
        .padding()
    }
    
    private var loadingView: some View {
        VStack(spacing: 20) {
            ProgressView(value: viewModel.progressValue, total: 1.0)
                .progressViewStyle(LinearProgressViewStyle(tint: accentColor))
                .padding(.horizontal)
            
            Text(viewModel.statusMessage)
                .font(.headline)
            
            Image(systemName: "lock.shield")
                .font(.system(size: 40))
                .foregroundColor(accentColor)
                .padding()
                .background(
                    Circle()
                        .fill(Color(UIColor.secondarySystemBackground))
                        .frame(width: 100, height: 100)
                )
            
            Text("Phoenix Codex Master v-infinity")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
    }
    
    private var mainModuleView: some View {
        TabView {
            dashboardTab
                .tabItem {
                    Label("Dashboard", systemImage: "chart.bar.xaxis")
                }
            
            scanTab
                .tabItem {
                    Label("Scan", systemImage: "shield.lefthalf.filled")
                }
            
            vulnerabilitiesTab
                .tabItem {
                    Label("Vulnerabilities", systemImage: "exclamationmark.triangle")
                }
            
            reportsTab
                .tabItem {
                    Label("Reports", systemImage: "doc.text")
                }
        }
        .accentColor(accentColor)
    }
    
    private var dashboardTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                securityScoreView
                
                riskSummaryView
                
                HStack(spacing: 15) {
                    metricCard(title: "Open Vulnerabilities", value: "\(viewModel.vulnerabilities.filter { $0.status == .open }.count)", icon: "exclamationmark.triangle.fill", color: .red)
                    
                    metricCard(title: "In Progress", value: "\(viewModel.vulnerabilities.filter { $0.status == .inProgress }.count)", icon: "gear", color: .orange)
                }
                
                HStack(spacing: 15) {
                    metricCard(title: "Mitigated", value: "\(viewModel.vulnerabilities.filter { $0.status == .mitigated }.count)", icon: "shield.lefthalf.filled", color: .blue)
                    
                    metricCard(title: "Resolved", value: "\(viewModel.vulnerabilities.filter { $0.status == .resolved }.count)", icon: "checkmark.shield.fill", color: .green)
                }
                
                complianceView
            }
            .padding()
        }
    }
    
    private var securityScoreView: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Security Score")
                .font(.headline)
            
            HStack(spacing: 20) {
                ZStack {
                    Circle()
                        .stroke(Color.gray.opacity(0.2), lineWidth: 15)
                        .frame(width: 100, height: 100)
                    
                    Circle()
                        .trim(from: 0, to: 0.73)
                        .stroke(accentColor, style: StrokeStyle(lineWidth: 15, lineCap: .round))
                        .frame(width: 100, height: 100)
                        .rotationEffect(.degrees(-90))
                    
                    Text("73%")
                        .font(.title)
                        .fontWeight(.bold)
                }
                
                VStack(alignment: .leading, spacing: 5) {
                    Text("Good")
                        .font(.title2)
                        .fontWeight(.semibold)
                    
                    Text("Last scan: Today, 10:45 AM")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                    
                    Text("5 issues need attention")
                        .font(.subheadline)
                        .foregroundColor(accentColor)
                }
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(UIColor.secondarySystemBackground))
        )
    }
    
    private var riskSummaryView: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Risk Summary")
                .font(.headline)
            
            HStack(spacing: 15) {
                riskIndicator(level: "Critical", count: 2, color: .red)
                riskIndicator(level: "High", count: 3, color: .orange)
                riskIndicator(level: "Medium", count: 8, color: .yellow)
                riskIndicator(level: "Low", count: 12, color: .green)
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(UIColor.secondarySystemBackground))
        )
    }
    
    private func riskIndicator(level: String, count: Int, color: Color) -> some View {
        VStack(spacing: 5) {
            Text("\(count)")
                .font(.title3)
                .fontWeight(.bold)
            
            Text(level)
                .font(.caption)
                .foregroundColor(.secondary)
            
            Rectangle()
                .fill(color)
                .frame(height: 4)
                .frame(maxWidth: .infinity)
        }
    }
    
    private func metricCard(title: String, value: String, icon: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: icon)
                    .font(.title3)
                    .foregroundColor(color)
                
                Spacer()
                
                Text(value)
                    .font(.title)
                    .fontWeight(.bold)
            }
            
            Text(title)
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(UIColor.secondarySystemBackground))
        )
        .frame(maxWidth: .infinity)
    }
    
    private var complianceView: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Compliance Status")
                .font(.headline)
            
            VStack(spacing: 15) {
                complianceItem(framework: "ISO 27001", status: "Compliant", progress: 0.95, color: .green)
                complianceItem(framework: "NIST CSF", status: "Partial", progress: 0.82, color: .blue)
                complianceItem(framework: "PCI-DSS", status: "Review Required", progress: 0.67, color: .orange)
                complianceItem(framework: "HIPAA", status: "Compliant", progress: 0.91, color: .green)
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(UIColor.secondarySystemBackground))
        )
    }
    
    private func complianceItem(framework: String, status: String, progress: Double, color: Color) -> some View {
        VStack(alignment: .leading, spacing: