package com.vulndetection.service;

import com.vulndetection.dto.CodeUploadRequest;
import com.vulndetection.dto.ScanResultDTO;
import com.vulndetection.entity.*;
import com.vulndetection.integration.DeepSeekClient;
import com.vulndetection.integration.SonarQubeClient;
import com.vulndetection.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@Slf4j
@Service
@RequiredArgsConstructor
public class CodeScanService {
    
    private final CodeStorageService codeStorageService;
    private final SonarQubeClient sonarQubeClient;
    private final DeepSeekClient deepSeekClient;
    private final GitService gitService;
    private final UserRepository userRepository;
    private final DetectionResultFileRepository detectionResultFileRepository;
    private final VulnerabilityItemRepository vulnerabilityItemRepository;
    private final DetectionRecordRepository detectionRecordRepository;
    
    @Value("${scan.polling-interval:3000}")
    private long pollingInterval;
    
    /**
     * 接收前端上传的代码，启动扫描流程
     */
    @Transactional
    public String uploadAndScan(CodeUploadRequest request) throws Exception {
        log.info("接收到代码上传请求: taskName={}, userId={}", request.getTaskName(), request.getUserId());
        
        User user = userRepository.findById(request.getUserId())
            .orElseThrow(() -> new RuntimeException("用户不存在"));
        
        String detectionFileId = UUID.randomUUID().toString();
        String codePath = codeStorageService.saveCodeFile(detectionFileId, request.getCodeFile());
        
        // 获取原始代码内容
        String originalCode = readOriginalCode(codePath, request.getCodeFile().getOriginalFilename());
        
        DetectionResultFile resultFile = new DetectionResultFile();
        resultFile.setDetectionFileId(detectionFileId);
        resultFile.setFileStorageAddress(codePath);
        resultFile.setFileName(request.getCodeFile().getOriginalFilename());
        resultFile.setFileSize(request.getCodeFile().getSize());
        resultFile.setScanType(request.getLanguage());
        resultFile.setScanStatus("PENDING");
        resultFile.setUser(user);
        detectionResultFileRepository.save(resultFile);
        
        // 异步执行扫描流程
        executeScanFlowAsync(detectionFileId, codePath, originalCode, request, user, resultFile);
        
        return detectionFileId;
    }
    
    /**
     * 读取原始代码内容
     */
    private String readOriginalCode(String codePath, String fileName) throws IOException {
        java.nio.file.Path path = Paths.get(codePath);
        if (Files.isDirectory(path)) {
            StringBuilder allCode = new StringBuilder();
            Files.walk(path)
                .filter(Files::isRegularFile)
                .filter(p -> p.toString().endsWith(".java") || 
                             p.toString().endsWith(".py") || 
                             p.toString().endsWith(".js") ||
                             p.toString().endsWith(".go"))
                .forEach(p -> {
                    try {
                        allCode.append("// 文件: ").append(p.getFileName().toString()).append("\n");
                        allCode.append(Files.readString(p)).append("\n\n");
                    } catch (IOException e) {
                        log.error("读取文件失败: {}", p, e);
                    }
                });
            return allCode.toString();
        } else {
            return Files.readString(path);
        }
    }
    
    /**
     * 异步执行完整的扫描流程
     */
    @Async
    @Transactional
    public CompletableFuture<Void> executeScanFlowAsync(
            String detectionFileId,
            String codePath,
            String originalCode,
            CodeUploadRequest request,
            User user,
            DetectionResultFile resultFile) {
        
        List<VulnerabilityItem> vulnerabilityItems = new ArrayList<>();
        
        try {
            updateScanStatus(resultFile, "SCANNING", "正在准备代码...");
            
            // ========== 1. 推送到 GitHub 触发云端扫描 ==========
            updateScanStatus(resultFile, "PREPARING", "正在推送到 GitHub 触发云端扫描...");
            
            String fileName = request.getCodeFile().getOriginalFilename();
            if (fileName == null || fileName.isEmpty()) {
                String ext = request.getLanguage() != null ? request.getLanguage() : "txt";
                fileName = "code_" + detectionFileId + "." + ext;
            }
            
            boolean pushSuccess = gitService.pushCodeToGitHub(detectionFileId, originalCode, fileName);
            
            String scanResult = null;
            
            if (pushSuccess) {
                updateScanStatus(resultFile, "SCANNING", "等待 SonarCloud 云端扫描（轮询中）...");
                
                // 使用配置的 SonarCloud 项目 Key
                String sonarProjectKey = "1971256_sonar-test";
                scanResult = sonarQubeClient.waitForScanCompletion(sonarProjectKey, "main");
                
                if (scanResult != null) {
                    log.info("成功获取 SonarCloud 扫描结果");
                    updateScanStatus(resultFile, "SCANNING", "SonarCloud 扫描完成，正在解析结果...");
                } else {
                    log.warn("SonarCloud 扫描超时，回退到本地扫描");
                    updateScanStatus(resultFile, "SCANNING", "云端扫描超时，使用本地扫描...");
                }
            }
            
            // ========== 2. 如果云端扫描失败，回退到本地 SonarQube 扫描 ==========
            if (scanResult == null) {
                updateScanStatus(resultFile, "SCANNING", "正在使用本地 SonarQube 扫描...");
                String localProjectKey = "project_" + detectionFileId.replace("-", "_");
                sonarQubeClient.createProject(localProjectKey, request.getTaskName());
                String scanId = sonarQubeClient.uploadAndScan(localProjectKey, codePath, request.getLanguage());
                scanResult = waitForLocalScanCompletion(localProjectKey, scanId);
            }
            
            // ========== 3. 解析 SonarQube 结果并保存漏洞 ==========
            updateScanStatus(resultFile, "SCANNING", "正在解析扫描结果...");
            vulnerabilityItems = parseAndSaveVulnerabilities(detectionFileId, scanResult);
            
            // ========== 4. DeepSeek AI 深度分析 ==========
            if (request.getEnableDeepSeek()) {
                
                if (vulnerabilityItems.isEmpty()) {
                    // SonarQube 没有发现漏洞，让 DeepSeek 主动扫描
                    updateScanStatus(resultFile, "ANALYZING", "SonarQube 未发现漏洞，正在使用 DeepSeek AI 进行深度代码分析...");
                    
                    log.info("SonarQube 未发现漏洞，调用 DeepSeek 主动扫描源代码");
                    List<DeepSeekClient.AIVulnerability> aiVulnerabilities = 
                        deepSeekClient.scanCodeForVulnerabilities(originalCode, request.getLanguage());
                    
                    if (aiVulnerabilities != null && !aiVulnerabilities.isEmpty()) {
                        for (DeepSeekClient.AIVulnerability aiVuln : aiVulnerabilities) {
                            VulnerabilityItem item = new VulnerabilityItem();
                            item.setVulnerabilityCategory(aiVuln.getCategory());
                            item.setCodeSnippet(aiVuln.getCodeSnippet());
                            item.setFixSuggestion(aiVuln.getSuggestion());
                            item.setCodeExample(aiVuln.getCodeExample());
                            item.setSeverity(aiVuln.getSeverity());
                            item.setFilePath(aiVuln.getFilePath());
                            item.setLineNumber(aiVuln.getLineNumber());
                            item.setSonarRule("AI_DETECTED_" + aiVuln.getCategory().toUpperCase().replace(" ", "_"));
                            item.setDeepSeekAnalysis(aiVuln.getFullAnalysis());
                            vulnerabilityItemRepository.save(item);
                            vulnerabilityItems.add(item);
                        }
                        log.info("DeepSeek AI 主动扫描发现 {} 个潜在漏洞", aiVulnerabilities.size());
                    } else {
                        log.info("DeepSeek AI 深度分析未发现漏洞");
                    }
                    
                } else {
                    // SonarQube 发现了漏洞，结合代码上下文进行深度分析
                    updateScanStatus(resultFile, "ANALYZING", "正在调用 DeepSeek AI 综合分析漏洞和代码...");
                    
                    List<DeepSeekClient.VulnerabilityAnalysis> analyses = 
                        deepSeekClient.analyzeVulnerabilitiesWithCode(vulnerabilityItems, originalCode);
                    
                    for (int i = 0; i < vulnerabilityItems.size() && i < analyses.size(); i++) {
                        VulnerabilityItem item = vulnerabilityItems.get(i);
                        DeepSeekClient.VulnerabilityAnalysis analysis = analyses.get(i);
                        
                        if (analysis != null) {
                            item.setFixSuggestion(analysis.getSuggestion());
                            item.setCodeExample(analysis.getCodeExample());
                            item.setDeepSeekAnalysis(analysis.getFullAnalysis());
                            vulnerabilityItemRepository.save(item);
                        }
                    }
                }
            }
            
            // ========== 5. 创建检测记录并更新最终状态 ==========
            createDetectionRecords(detectionFileId, vulnerabilityItems, user, resultFile);
            
            resultFile.setTotalVulnerabilities(vulnerabilityItems.size());
            resultFile.setScanStatus("COMPLETED");
            
            String summary = vulnerabilityItems.isEmpty() ? 
                "扫描完成，未发现安全漏洞" : 
                String.format("扫描完成，共发现 %d 个安全漏洞", vulnerabilityItems.size());
            resultFile.setScanSummary(summary);
            detectionResultFileRepository.save(resultFile);
            
            log.info("扫描流程完成: detectionFileId={}, 漏洞数={}", detectionFileId, vulnerabilityItems.size());
            
        } catch (Exception e) {
            log.error("扫描流程失败: detectionFileId={}", detectionFileId, e);
            resultFile.setScanStatus("FAILED");
            resultFile.setScanSummary("扫描失败: " + e.getMessage());
            detectionResultFileRepository.save(resultFile);
        }
        
        return CompletableFuture.completedFuture(null);
    }
    
    /**
     * 更新扫描状态
     */
    private void updateScanStatus(DetectionResultFile resultFile, String status, String message) {
        resultFile.setScanStatus(status);
        resultFile.setScanSummary(message);
        detectionResultFileRepository.save(resultFile);
        log.debug("扫描状态更新: status={}, message={}", status, message);
    }
    
    /**
     * 等待本地 SonarQube 扫描完成
     */
    private String waitForLocalScanCompletion(String projectKey, String scanId) throws InterruptedException {
        int maxRetries = 60;
        for (int i = 0; i < maxRetries; i++) {
            Thread.sleep(pollingInterval);
            String status = sonarQubeClient.getScanStatus(projectKey, scanId);
            if ("SUCCESS".equals(status)) {
                return sonarQubeClient.getScanResults(projectKey);
            } else if ("FAILED".equals(status)) {
                throw new RuntimeException("本地 SonarQube 扫描失败");
            }
        }
        throw new RuntimeException("本地 SonarQube 扫描超时");
    }
    
    /**
     * 解析 SonarQube 结果并保存漏洞
     */
    private List<VulnerabilityItem> parseAndSaveVulnerabilities(String detectionFileId, String scanResult) {
        List<VulnerabilityItem> items = new ArrayList<>();
        List<SonarQubeClient.Issue> issues = sonarQubeClient.getIssuesList(scanResult);
        
        for (SonarQubeClient.Issue issue : issues) {
            VulnerabilityItem item = new VulnerabilityItem();
            item.setVulnerabilityCategory(mapRuleToCategory(issue.getRule()));
            item.setCodeSnippet(issue.getMessage());
            item.setSeverity(issue.getSeverity());
            item.setFilePath(issue.getComponent());
            item.setLineNumber(issue.getLine());
            item.setSonarRule(issue.getRule());
            vulnerabilityItemRepository.save(item);
            items.add(item);
        }
        return items;
    }
    
    /**
     * DeepSeek 分析漏洞
     */
    private void analyzeWithDeepSeek(List<VulnerabilityItem> items) {
        for (VulnerabilityItem item : items) {
            try {
                DeepSeekClient.AnalysisResponse response = deepSeekClient.analyzeVulnerability(
                    item.getVulnerabilityCategory(),
                    item.getCodeSnippet(),
                    item.getSeverity()
                );
                item.setFixSuggestion(response.getSuggestion());
                item.setCodeExample(response.getCodeExample());
                item.setDeepSeekAnalysis(response.getFullAnalysis());
                vulnerabilityItemRepository.save(item);
                Thread.sleep(500);
            } catch (Exception e) {
                log.error("DeepSeek 分析失败", e);
            }
        }
    }
    
    /**
     * 创建检测记录
     */
    private void createDetectionRecords(String detectionFileId, List<VulnerabilityItem> items, User user, DetectionResultFile resultFile) {
        for (VulnerabilityItem item : items) {
            DetectionRecord record = new DetectionRecord();
            record.setDetectionFileId(detectionFileId);
            record.setVulnerabilityItemId(item.getVulnerabilityItemId());
            record.setUser(user);
            record.setDetectionResultFile(resultFile);
            record.setVulnerabilityItem(item);
            detectionRecordRepository.save(record);
        }
    }
    
    /**
     * 将 SonarQube 规则映射到漏洞类别
     */
    private String mapRuleToCategory(String rule) {
        if (rule == null) return "未知漏洞";
        if (rule.toLowerCase().contains("sql")) return "SQL注入漏洞";
        if (rule.toLowerCase().contains("xss")) return "跨站脚本(XSS)";
        if (rule.toLowerCase().contains("path")) return "路径遍历漏洞";
        if (rule.toLowerCase().contains("command")) return "命令注入漏洞";
        return "代码安全漏洞";
    }
    
    /**
     * 获取扫描结果
     */
    public ScanResultDTO getScanResult(String detectionFileId) {
        DetectionResultFile resultFile = detectionResultFileRepository.findByDetectionFileId(detectionFileId)
            .orElseThrow(() -> new RuntimeException("扫描任务不存在: " + detectionFileId));
        
        ScanResultDTO result = new ScanResultDTO();
        result.setTaskId(detectionFileId);
        result.setStatus(resultFile.getScanStatus());
        result.setTotalVulnerabilities(resultFile.getTotalVulnerabilities());
        result.setFileStorageAddress(resultFile.getFileStorageAddress());
        result.setDetectionTime(resultFile.getDetectionTime());
        
        // 获取漏洞详情
        List<DetectionRecord> records = detectionRecordRepository.findByDetectionFileId(detectionFileId);
        List<ScanResultDTO.VulnerabilityDTO> vulnDTOs = new ArrayList<>();
        
        for (DetectionRecord record : records) {
            VulnerabilityItem item = record.getVulnerabilityItem();
            if (item != null) {
                ScanResultDTO.VulnerabilityDTO dto = new ScanResultDTO.VulnerabilityDTO();
                dto.setVulnerabilityCategory(item.getVulnerabilityCategory());
                dto.setCodeSnippet(item.getCodeSnippet());
                dto.setFixSuggestion(item.getFixSuggestion());
                dto.setCodeExample(item.getCodeExample());
                dto.setSeverity(item.getSeverity());
                dto.setFilePath(item.getFilePath());
                dto.setLineNumber(item.getLineNumber());
                vulnDTOs.add(dto);
            }
        }
        
        result.setVulnerabilities(vulnDTOs);
        return result;
    }
    
    /**
     * 获取用户的所有检测记录
     */
    public List<DetectionResultFile> getUserScanHistory(Long userId) {
        return detectionResultFileRepository.findByUser_UserId(userId);
    }
    
    /**
     * SonarCloud 扫描完成后的回调（可通过 Webhook 触发）
     */
    @Transactional
    public void onSonarScanComplete(String projectKey) {
        log.info("收到 SonarCloud 扫描完成回调: projectKey={}", projectKey);
        
        // 可以根据 projectKey 找到对应的 detectionFileId
        List<DetectionResultFile> files = detectionResultFileRepository.findByScanStatus("SCANNING");
        for (DetectionResultFile file : files) {
            if (file.getScanSummary() != null && file.getScanSummary().contains(projectKey)) {
                // 重新获取扫描结果
                String scanResult = sonarQubeClient.getScanResults(projectKey);
                if (scanResult != null) {
                    // 处理扫描结果...
                    log.info("成功获取 SonarCloud 扫描结果，更新检测记录: {}", file.getDetectionFileId());
                }
                break;
            }
        }
    }
}