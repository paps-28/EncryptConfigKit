package com.crypt.crypto_api_demo.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/crypto")
public class CryptoController {
    @PostMapping({"/public-key", "/public-key-with-file"})
    public void receivePublicKey() {
        throw new ResponseStatusException(HttpStatus.GONE, "Attestation required");
    }
}
