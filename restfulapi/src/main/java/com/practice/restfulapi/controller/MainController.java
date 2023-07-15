package com.practice.restfulapi.controller;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.practice.restfulapi.resource.DynamicIV_Encrypt_Decrypt;

@RestController
public class MainController {
	@GetMapping("test")
	public String testModel() {
		return "The api is working";
	}
	
	@GetMapping("enc")
	public String encryptModel(
			@RequestParam(name = "dataToEncrypt",required = false) String dataToEncrypt, 
            @RequestParam(name = "secretHexKey",required = false) String secretHexKey) throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
		
		String token = DynamicIV_Encrypt_Decrypt.encrypt(dataToEncrypt, secretHexKey);
		System.out.println(token);
		return token;
	}
	
	@GetMapping("dec")
	public String decryptModel(
			@RequestParam(name = "encrypted",required = false) String encrypted, 
            @RequestParam(name = "secretHexKey",required = false) String secretHexKey) throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
		
		String token = DynamicIV_Encrypt_Decrypt.decrypt(encrypted, secretHexKey);
		System.out.println("Value of decrypted token is: "+token);
		return token;
	}
}
