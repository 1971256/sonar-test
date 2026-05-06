package com.example.controller;

import java.sql.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    // ============ 漏洞1: SQL注入 ============
    @GetMapping("/user")
    public String getUser(@RequestParam String id) {
        // 危险：直接拼接用户输入到SQL查询中
        String sql = "SELECT * FROM users WHERE id = " + id;
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "root", "password");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            return rs.getString("username");
        } catch (SQLException e) {
            return "Error: " + e.getMessage();
        }
    }

    // ============ 漏洞2: XSS跨站脚本 ============
    @GetMapping("/search")
    public String search(@RequestParam String keyword) {
        // 危险：直接输出用户输入，未进行HTML编码
        String html = "<div>搜索结果: " + keyword + "</div>";
        html += "<script>console.log('搜索: " + keyword + "')</script>";
        return html;
    }

    // ============ 漏洞3: 路径遍历 ============
    @GetMapping("/download")
    public void downloadFile(@RequestParam String filename, HttpServletResponse response) {
        // 危险：未验证文件路径，可能导致读取任意文件
        String basePath = "/var/www/uploads/";
        String filePath = basePath + filename;
        
        try {
            File file = new File(filePath);
            // 未检查文件是否在允许的目录内
            FileInputStream fis = new FileInputStream(file);
            // ... 输出文件
        } catch (IOException e) {
            // 危险：错误信息泄露系统路径
            response.setStatus(500);
        }
    }

    // ============ 漏洞4: 敏感信息泄露 ============
    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        // 危险：记录敏感信息到日志
        System.out.println("用户登录尝试 - 用户名: " + username + ", 密码: " + password);
        
        if ("admin".equals(username) && "123456".equals(password)) {
            return "登录成功";
        }
        return "登录失败";
    }

    // ============ 漏洞5: 命令注入 ============
    @GetMapping("/ping")
    public String ping(@RequestParam String ip) {
        // 危险：直接拼接命令
        String cmd = "ping -c 4 " + ip;
        
        try {
            Process process = Runtime.getRuntime().exec(cmd);
            // ... 执行系统命令
            return "命令执行成功";
        } catch (IOException e) {
            return "执行失败";
        }
    }

    // ============ 漏洞6: 不安全的加密 ============
    public String encryptPassword(String password) {
        try {
            // 危险：使用不安全的加密算法
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(password.getBytes());
            return new String(digest);
        } catch (Exception e) {
            return password;
        }
    }

    // ============ 漏洞7: 空密码/弱密码 ============
    public void createUser(String username, String password) {
        // 危险：允许空密码或弱密码
        if (password == null || password.isEmpty()) {
            password = "123456"; // 默认弱密码
        }
        // 保存用户...
    }
}