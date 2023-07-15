package com.practice.restfulapi.resource;

import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;

public class DynamicIV_Encrypt_Decrypt
{
  private static SecureRandom random = new SecureRandom();
  private static final int lowAsciiLimit = 47;
  private static final int highAsciiLimit = 126;
  private static String initVector;
  private static IvParameterSpec ivSpec;
  private static SecretKeySpec skeySpec;
  private static Cipher cipher;
  private static String finalEncryptedPayload = "";
  private static String decryptedText = "";

  public static String generateIv()
  {
    int ivLength = 16;
    StringBuilder finalIvBuffer = new StringBuilder(ivLength);
    for (int i = 0; i < ivLength; i++) {
      int randomNumber = 47 + (int)(random.nextFloat() * 80.0F);
      finalIvBuffer.append((char)randomNumber);
    }
    return finalIvBuffer.toString();
  }

  public static String encrypt(String dataToEncrypt, String secretHexKey)
    throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
  {
    try
    {
      finalEncryptedPayload = "";

      byte[] secretKeyHexbytes = Hex.decodeHex(secretHexKey.toCharArray());

      initVector = generateIv();
      System.out.println(new StringBuilder().append("Dynamic IV: ").append(initVector).toString());

      ivSpec = new IvParameterSpec(initVector.getBytes("UTF-8"));

      if ((secretKeyHexbytes.length == 32) || (secretKeyHexbytes.length == 24) || (secretKeyHexbytes.length == 16))
        skeySpec = new SecretKeySpec(secretKeyHexbytes, "AES");
      else {
        throw new Exception("Invalid Key Length, Must be 16/24/32 bytes");
      }

      cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

      cipher.init(1, skeySpec, ivSpec);

      byte[] encryptedBytes = cipher.doFinal(dataToEncrypt.toString().getBytes());

      byte[] finalarray = new byte[initVector.length() + encryptedBytes.length];

      System.arraycopy(initVector.getBytes(), 0, finalarray, 0, initVector.getBytes().length);

      System.arraycopy(encryptedBytes, 0, finalarray, initVector.getBytes().length, encryptedBytes.length);

      finalEncryptedPayload = Base64.getEncoder().encodeToString(finalarray);

      return finalEncryptedPayload;
    }
    catch (UnsupportedEncodingException exc) {
      System.out.println(exc.getMessage());
      return finalEncryptedPayload;
    } catch (NoSuchAlgorithmException exc) {
      System.out.println(exc.getMessage());
      return finalEncryptedPayload;
    } catch (NoSuchPaddingException exc) {
      System.out.println(exc.getMessage());
      return finalEncryptedPayload;
    } catch (InvalidKeyException exc) {
      System.out.println(exc.getMessage());
      return finalEncryptedPayload;
    } catch (InvalidAlgorithmParameterException exc) {
      System.out.println(exc.getMessage());
      return finalEncryptedPayload;
    } catch (IllegalBlockSizeException exc) {
      System.out.println(exc.getMessage());
      return finalEncryptedPayload;
    } catch (BadPaddingException exc) {
      System.out.println(exc.getMessage());
      return finalEncryptedPayload;
    } catch (Exception exc) {
      System.out.println(exc.getMessage());
    }return finalEncryptedPayload;
  }

  public static String decrypt(String encrypted, String secretKey)
    throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
  {
    try
    {
    	System.out.println("Executing Decrypt");
    	
      decryptedText = "";
      
      System.out.println("Before SecretKey to Char Array");
      
      byte[] secretKeyHexbytes = Hex.decodeHex(secretKey.toCharArray());
      
      System.out.println("Value of secretKeyHexbytes is : "+secretKeyHexbytes);
      
      if ((secretKeyHexbytes.length == 32) || (secretKeyHexbytes.length == 24) || (secretKeyHexbytes.length == 16))
        skeySpec = new SecretKeySpec(secretKeyHexbytes, "AES");
      else {
        throw new Exception("Invalid Key Length, Must be 16/24/32 bytes");
      }

      byte[] encryptedCombinedBytes = Base64.getDecoder().decode(encrypted);

      byte[] iv = Arrays.copyOfRange(encryptedCombinedBytes, 0, 16);

      byte[] encryptedPayload = Arrays.copyOfRange(encryptedCombinedBytes, iv.length, encryptedCombinedBytes.length);

      ivSpec = new IvParameterSpec(iv);

      cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

      cipher.init(2, skeySpec, ivSpec);

      byte[] decryptedBytes = cipher.doFinal(encryptedPayload);

      decryptedText = new String(decryptedBytes);
      System.out.println("Checking here");
      return decryptedText;
    }
    catch (NoSuchAlgorithmException exc) {
      System.out.println(exc.getMessage());
      System.out.println("Checking here 1");
      return decryptedText;
    } catch (NoSuchPaddingException exc) {
      System.out.println(exc.getMessage());
      System.out.println("Checking here 2");
      return decryptedText;
    } catch (InvalidKeyException exc) {
      System.out.println(exc.getMessage());
      System.out.println("Checking here 3");
      return decryptedText;
    } catch (InvalidAlgorithmParameterException exc) {
      System.out.println(exc.getMessage());
      System.out.println("Checking here 4");
      return decryptedText;
    } catch (IllegalBlockSizeException exc) {
      System.out.println(exc.getMessage());
      System.out.println("Checking here 5");
      return decryptedText;
    } catch (BadPaddingException exc) {
      System.out.println(exc.getMessage());
      System.out.println("Checking here 6");
      return decryptedText;
    } catch (Exception exc) {
      System.out.println(exc.getMessage());
      System.out.println("Checking here 7");
    }return decryptedText;
  }
}