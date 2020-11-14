package com.stefanodottori.javaaesfrasesunip;


import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.JOptionPane;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author Stefano Dottori - RA: T530IF4
 */
public class AESFrasesUNIP {

    private static final String AES = "AES";

    
    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5PADDING";

    

    /*
    função para criar a chave AES
    */
    public static SecretKey criaChaveAES()
            throws Exception {
        SecureRandom securerandom
                = new SecureRandom();
        KeyGenerator keygenerator
                = KeyGenerator.getInstance(AES);

        keygenerator.init(256, securerandom);
        SecretKey key
                = keygenerator.generateKey();

        return key;
    }

    // função para iniciar o vetor de criptografia 
    public static byte[] criaVetorDeInicializacao() {

        // utilizando com encriptação
        byte[] initializationVector
                = new byte[16];
        SecureRandom secureRandom
                = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }

     
    public static byte[] encriptaAES(
            String textoPuro,
            SecretKey chaveSecreta,
            byte[] initializationVector)
            throws Exception {
        Cipher cipher
                = Cipher.getInstance(
                        AES_CIPHER_ALGORITHM);

        IvParameterSpec ivParameterSpec
                = new IvParameterSpec(
                        initializationVector);

        cipher.init(Cipher.ENCRYPT_MODE,
                chaveSecreta,
                ivParameterSpec);

        return cipher.doFinal(
                textoPuro.getBytes());
    }

     
    public static String decriptaAES(
            byte[] textoCifrado,
            SecretKey chaveSecreta,
            byte[] initializationVector)
            throws Exception {
        Cipher cipher
                = Cipher.getInstance(
                        AES_CIPHER_ALGORITHM);

        IvParameterSpec ivParameterSpec
                = new IvParameterSpec(
                        initializationVector);

        cipher.init(
                Cipher.DECRYPT_MODE,
                chaveSecreta,
                ivParameterSpec);

        byte[] resultado
                = cipher.doFinal(textoCifrado);

        return new String(resultado);
    }

    
    public static void main(String args[])
            throws Exception {
        SecretKey chaveSimetrica
                = criaChaveAES();

        JOptionPane.showMessageDialog(null, "A chave AES é: " + DatatypeConverter.printHexBinary(
                chaveSimetrica.getEncoded()));

        byte[] initializationVector
                = criaVetorDeInicializacao();

        String textoPuro
                = JOptionPane.showInputDialog(null, "Digite a frase que deseja encriptar");

        /* Encripta a mensagem
        utilizando a chave AES criada
        */ 
         
        byte[] textoCifrado
                = encriptaAES(
                        textoPuro,
                        chaveSimetrica,
                        initializationVector);

        JOptionPane.showMessageDialog(null, "O texto cifrado ou mensagem encriptada é: " + DatatypeConverter.printHexBinary(
                textoCifrado));

        /*
        decripta a mensagem 
        */
        String decryptedText
                = decriptaAES(
                        textoCifrado,
                        chaveSimetrica,
                        initializationVector);

        JOptionPane.showMessageDialog(null, "A frase original era: " + decryptedText);

    }
}


