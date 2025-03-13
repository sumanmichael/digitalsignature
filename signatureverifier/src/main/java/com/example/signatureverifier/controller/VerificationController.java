package com.example.signatureverifier.controller;

import com.example.signatureverifier.model.SignaturePayload;
import com.example.signatureverifier.service.SignatureVerificationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class VerificationController {

    private final SignatureVerificationService verificationService;

    @Autowired
    public VerificationController(SignatureVerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @PostMapping("/verify")
    public ResponseEntity<Object> verifySignature(@RequestBody SignaturePayload payload) {
        boolean isValid = verificationService.verifySignature(payload);

        if (isValid) {
            return ResponseEntity.ok().body(
                    Map.of(
                            "status", "success",
                            "message", "Signature verification successful",
                            "data", payload.getContent()));
        } else {
            return ResponseEntity.badRequest().body(
                    Map.of(
                            "status", "error",
                            "message", "Invalid signature"));
        }
    }
}