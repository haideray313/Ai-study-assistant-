package com.mytutorial.aistudyassisstance;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.regex.Pattern;

@Controller
public class LoginController {

    @Autowired
    private UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    // Only lowercase alphabets (a-z), min 3 chars
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-z]{3,30}$");

    // At least 1 uppercase, 1 lowercase, 1 number, 1 special char, min 8 chars
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#^()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]).{8,}$"
    );

    @GetMapping({"/", "/login"})
    public String showLoginPage() {
        return "login";
    }

    @GetMapping("/signup")
    public String showSignupPage() {
        return "signup";
    }

    @GetMapping("/forgot-password")
    public String showForgotPasswordPage() {
        return "forgot-password";
    }

    @PostMapping("/register")
    public String registerUser(@RequestParam String username,
                               @RequestParam String password,
                               Model model) {

        if (!USERNAME_PATTERN.matcher(username).matches()) {
            model.addAttribute("error", "Username must contain only lowercase letters (a-z), at least 3 characters.");
            return "signup";
        }

        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            model.addAttribute("error", "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.");
            return "signup";
        }

        if (userRepository.existsByUsername(username)) {
            model.addAttribute("error", "Username already exists in the database.");
            return "signup";
        }

        String hashedPassword = passwordEncoder.encode(password);
        User newUser = new User(username, hashedPassword);
        userRepository.save(newUser);

        return "redirect:/login?registered=true";
    }

    @PostMapping("/authenticate")
    public String authenticateUser(@RequestParam String username,
                                   @RequestParam String password,
                                   HttpSession session) {

        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isPresent() && passwordEncoder.matches(password, userOpt.get().getPassword())) {
            session.setAttribute("loggedInUser", username);
            return "redirect:/home";
        }

        return "redirect:/login?error=true";
    }

    @PostMapping("/reset-password")
    public String resetPassword(@RequestParam String username,
                                @RequestParam String newPassword,
                                @RequestParam String confirmPassword,
                                Model model) {

        if (!USERNAME_PATTERN.matcher(username).matches()) {
            model.addAttribute("error", "Invalid username format (only lowercase letters allowed).");
            return "forgot-password";
        }

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            model.addAttribute("error", "Username not found in database.");
            return "forgot-password";
        }

        if (!newPassword.equals(confirmPassword)) {
            model.addAttribute("error", "Passwords do not match.");
            return "forgot-password";
        }

        if (!PASSWORD_PATTERN.matcher(newPassword).matches()) {
            model.addAttribute("error", "New password must include uppercase, lowercase, number, and special character (min 8 chars).");
            return "forgot-password";
        }

        User user = userOpt.get();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        return "redirect:/login?resetSuccess=true";
    }

    @GetMapping("/home")
    public String showHomePage(HttpSession session, Model model) {
        String username = (String) session.getAttribute("loggedInUser");
        if (username == null) {
            return "redirect:/login";
        }
        model.addAttribute("username", username);
        return "home";
    }

    @GetMapping("/contact")
    public String showContactPage(HttpSession session, Model model) {
        String username = (String) session.getAttribute("loggedInUser");
        if (username == null) {
            return "redirect:/login";
        }
        model.addAttribute("username", username);
        return "contact";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login?logout=true";
    }
}