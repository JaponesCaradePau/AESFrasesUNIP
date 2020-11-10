package com.stefanodottori.javarsafrasesunip;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
 
import javax.crypto.Cipher;
import javax.swing.JOptionPane;


/**
 *
 * @author Stefano Dottori - RA: T530IF4
 */
public class RSAFrasesUNIP {
     public static void main(String[] args) throws Exception {
        
 
       String plainText =  JOptionPane.showInputDialog(null,"Digite a frase que deseja encriptar");
        
        
        // Gera as chaves publicas e privadas usando RSA
        Map<String, Object> keys = getRSAKeys();
 
        PrivateKey privateKey = (PrivateKey) keys.get("private");
        PublicKey publicKey = (PublicKey) keys.get("public");
 
        String encryptedText = encryptMessage(plainText, privateKey);
        String descryptedText = decryptMessage(encryptedText, publicKey);
 
        JOptionPane.showMessageDialog(null,"A frase digitada foi: " + plainText);
        JOptionPane.showMessageDialog(null,"A fase encriptada é: " + encryptedText);
        JOptionPane.showMessageDialog(null,"A frase não encriptada é: " + descryptedText);
 
    }
 
    // Obtem as chaves RSA. Vai utilizar o tamanho de 2048 bits.
    private static Map<String,Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
 
        Map<String, Object> keys = new HashMap<>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }
 
    // Decripta a frase utilizando a chave publica do RSA 
    private static String decryptMessage(String encryptedText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }
 
    // Encripta a frase utilizando a chave privadada do RSA 
    private static String encryptMessage(String plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
 
}

