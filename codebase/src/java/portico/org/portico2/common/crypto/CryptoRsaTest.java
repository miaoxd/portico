/*
 *   Copyright 2018 The Portico Project
 *
 *   This file is part of portico.
 *
 *   portico is free software; you can redistribute it and/or modify
 *   it under the terms of the Common Developer and Distribution License (CDDL) 
 *   as published by Sun Microsystems. For more information see the LICENSE file.
 *   
 *   Use of this software is strictly AT YOUR OWN RISK!!!
 *   If something bad happens you do not have permission to come crying to me.
 *   (that goes for your lawyer as well)
 *
 */
package org.portico2.common.crypto;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.portico.lrc.compat.JConfigurationException;

/*
 * Generating Keys with ssh-keygen
 *    * ssh-keygen -t rsa -b 4096 -C "example@example.com"   // produces id_rsa/id_rsa.pub
 *    * ssh-keygen -f id_rsa.pub -e -m pem > id_rsa.pem      // turn the .pub file into PEM formatted
 * 
 * Generating Keys with OpenSSL
 *    * openssl genrsa -aes128 -out private.pem 2048                       // Generate private key
 *    * openssl rsa -in private.pem -outform PEM -pubout -out public.pem   // Generate public key
 */
public class CryptoRsaTest
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------
	static { Security.addProvider( new BouncyCastleFipsProvider() ); }

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------

	public void run() throws Exception
	{
		// 1. Prepare the inputs
		String message = "The cow kicked Nelly in the belly in the barn. Didn't do her no good, didn't do her no harm";

		// 2. Generate a Key Pair
		System.out.print( "Generating key pair..." );
		KeyPair keys = generateKeys();
		System.out.println( "done" );
		
		// 3. Encrypt the Data
		System.out.println( "Encrypting..." );
		byte[] encrypted = encrypt( message, keys.getPublic() );

		// 4. Decrypt the Data
		System.out.println( "Decrypting..." );
		String decrypted = decrypt( encrypted, keys.getPrivate() );
		
		// 5. Compare
		if( decrypted.equals(message) == false )
		{
			System.out.println( "FAILURE: Messages are not equal" );
			System.out.println( " [before] "+message );
			System.out.println( "  [after] "+decrypted );
		}
		else
		{
			System.out.println( "Messages match!" );
		}
		
		// 6. Write the data to a PEM String
//		String pemPublic = encodePublicKeyPEM( keys.getPublic() );
//		String pemPrivate = encodePrivateKeyPEM( keys.getPrivate() );
//		System.out.println( ">>>>>> PEM ENCODING <<<<<<" );
//		System.out.println( "Public Key: " );
//		System.out.println( pemPublic );
//		System.out.println( "Private Key: " );
//		System.out.println( pemPrivate );
//		
//		System.out.println( ">>>>>> PEM ENCODING ENCRYPTED <<<<<<" );
//		String password = String.format( "%16s", "evelyn" ); // 16-bytes (128-bit to match AES-256)
//		String pemPublicEnc = encodePublicKeyPEMEncrypted( password.toCharArray(), keys.getPublic() );
//		String pemPrivateEnc = encodePrivateKeyPEMEncrypted( password.toCharArray(), keys.getPrivate() );
//		System.out.println( "Public Key: " );
//		System.out.println( pemPublicEnc );
//		System.out.println( "Private Key: " );
//		System.out.println( pemPrivateEnc );

		
		// 7. Read PEM File
		//File privateKeyFile = new File( "id_rsa" );
		File privateKeyFile = new File( "private.pem" );
		PrivateKey privateKey = readPrivateKeyPemFile( privateKeyFile, "password".toCharArray() );
		System.out.println( "Read private key: "+privateKey.getFormat() );
		System.out.println( "Read private key: "+privateKey.getAlgorithm() );
		
		//File publicKeyFile = new File( "id_rsa.pem" );
		File publicKeyFile = new File( "public.pem" );
		PublicKey publicKey = readPublicKeyPemFile( publicKeyFile );
		System.out.println( "Read public key: "+publicKey.getFormat() );
		System.out.println( "Read public key: "+publicKey.getAlgorithm() );
		
		KeyPair lePair = readKeyPairPemFile( privateKeyFile, "password".toCharArray() );
		System.out.println( " == Both from Private Key Only ==" );
		System.out.println( "Read private key: "+lePair.getPrivate().getFormat() );
		System.out.println( "Read private key: "+lePair.getPrivate().getAlgorithm() );
		System.out.println( "Read public key: "+lePair.getPublic().getFormat() );
		System.out.println( "Read public key: "+lePair.getPublic().getAlgorithm() );
		
		System.out.println( "Compare Public: "+(lePair.getPublic().equals(publicKey)) );
		
		System.out.println( "Finished" );
	}
	
	private KeyPair generateKeys() throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize( 2048 );
		return generator.genKeyPair();
	}
	
	private byte[] encrypt( String message, Key key ) throws Exception
	{
		Cipher cipher = Cipher.getInstance( "RSA" );
		cipher.init( Cipher.ENCRYPT_MODE, key );
		return cipher.doFinal( message.getBytes() );
	}

	public String decrypt( byte[] message, Key key ) throws Exception
	{
		Cipher cipher = Cipher.getInstance( "RSA" );
		cipher.init( Cipher.DECRYPT_MODE, key );
		byte[] bytes = cipher.doFinal( message );
		return new String( bytes );
	}

	////////////////////////////////////////////////////////////////////////////////////////
	///  General Utility Methods   /////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////

	
	////////////////////////////////////////////////////////////////////////////////////////
	///  Key Storage, Binary   /////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////
	//
	// Public Key Encoding and Decoding -- PBKDS
	// Example 61
	//
	public byte[] encodePublicKeyPBKDS( PublicKey publicKey )
	{
		return publicKey.getEncoded();
	}

	public PublicKey decodePublicKeyPBKDS( byte[] encoding ) throws GeneralSecurityException
	{
		KeyFactory factory = KeyFactory.getInstance( "RSA", "BCFIPS" );
		return factory.generatePublic( new X509EncodedKeySpec(encoding) );
	}
	
	//
	// Private Key Encoding and Decoding -- PBKDS
	// Example 62
	//
	public byte[] encodePrivateKeyPBKDS( PrivateKey privateKey )
	{
		return privateKey.getEncoded();
	}

	public PrivateKey decodePrivateKeyPBKDS( byte[] encoding ) throws GeneralSecurityException
	{
		KeyFactory factory = KeyFactory.getInstance( "RSA", "BCFIPS" );
		return factory.generatePrivate( new PKCS8EncodedKeySpec(encoding) );
	}

	////////////////////////////////////////////////////////////////////////////////////////
	///  Key Storage, Text/PEM   ///////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////
	//
	// Private Key Encoding and Decoding - PEM
	// Example 64
	//
	public String encodePrivateKeyPEM( PrivateKey privateKey ) throws IOException
	{
		StringWriter stringWriter = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter( stringWriter );
		pemWriter.writeObject( privateKey );
		pemWriter.close();
		return stringWriter.toString();
	}

	public PrivateKey decodePrivateKeyPEM( String pemEncoding ) throws IOException
	{
		PEMParser parser = new PEMParser( new StringReader(pemEncoding) );
		PEMKeyPair pemKeyPair = (PEMKeyPair)parser.readObject();
		parser.close();
		return new JcaPEMKeyConverter().getPrivateKey( pemKeyPair.getPrivateKeyInfo() );
	}

	//
	// Private Key Encoding and Decoding - PEM, Encrypted (Password)
	// Example 66
	//
	public String encodePrivateKeyPEMEncrypted( char[] password, PrivateKey privateKey ) throws IOException
	{
		StringWriter stringWriter = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter( stringWriter );
		JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder("AES-128-CBC").setProvider("BCFIPS");
		pemWriter.writeObject( privateKey, builder.build(password) );
		pemWriter.close();
		return stringWriter.toString();
	}

	public PrivateKey decodePrivateKeyPEMEncrypted( char[] password, String pemEncoding ) throws IOException
	{
		PEMParser parser = new PEMParser( new StringReader(pemEncoding) );
		PEMEncryptedKeyPair pemEncryptedKeyPair = (PEMEncryptedKeyPair)parser.readObject();
		parser.close();
		PEMDecryptorProvider pkcs8Provider = new JcePEMDecryptorProviderBuilder().setProvider("BCFIPS").build(password);
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider( "BCFIPS" );
		return converter.getPrivateKey( pemEncryptedKeyPair.decryptKeyPair(pkcs8Provider).getPrivateKeyInfo() );
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	public KeyPair readKeyPairPemFile( File file, char[] password/*optional*/ ) throws IOException
	{
		// Extract the PemObject (metadata) and Key Pair (hopefully) from the file
		PEMParser parser = new PEMParser( new FileReader(file) );
		Object temp = parser.readObject();
		parser.close();

		if( temp instanceof PEMKeyPair )
		{
			// Unencrypted
			PEMKeyPair pair = (PEMKeyPair)temp;
			return new JcaPEMKeyConverter().getKeyPair( pair );
		}
		else if( temp instanceof PEMEncryptedKeyPair )
		{
			// Encrypted
			if( password == null || password.length == 0 )
				throw new JConfigurationException( "Private Key load error: Encrypted, but no password provided. "+file );
			
			PEMEncryptedKeyPair pair = (PEMEncryptedKeyPair)temp;
			PEMDecryptorProvider pkcs8 = new JcePEMDecryptorProviderBuilder().setProvider("BCFIPS").build(password);
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BCFIPS");
			return converter.getKeyPair( pair.decryptKeyPair(pkcs8) );
		}
		
		// We don't know what we read...
		throw new JConfigurationException( "Private Key load error: Unsupported ("+temp.getClass()+")" );
	}
	
	public PrivateKey readPrivateKeyPemFile( File file, char[] password/*optional*/ ) throws IOException
	{
		// Extract the PemObject (metadata) and Key Pair (hopefully) from the file
		PEMParser parser = new PEMParser( new FileReader(file) );
		Object temp = parser.readObject();
		parser.close();

		if( temp instanceof PEMKeyPair )
		{
			// Unencrypted
			PEMKeyPair pair = (PEMKeyPair)temp;
			return new JcaPEMKeyConverter().getPrivateKey( pair.getPrivateKeyInfo() );
		}
		else if( temp instanceof PEMEncryptedKeyPair )
		{
			// Encrypted
			if( password == null || password.length == 0 )
				throw new JConfigurationException( "Private Key load error: Encrypted, but no password provided. "+file );
			
			PEMEncryptedKeyPair pair = (PEMEncryptedKeyPair)temp;
			PEMDecryptorProvider pkcs8 = new JcePEMDecryptorProviderBuilder().setProvider("BCFIPS").build(password);
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BCFIPS");
			return converter.getPrivateKey( pair.decryptKeyPair(pkcs8).getPrivateKeyInfo() );
		}
		
		// We don't know what we read...
		throw new JConfigurationException( "Private Key load error: Unsupported ("+temp.getClass()+")" );
	}
	
	public PublicKey readPublicKeyPemFile( File file ) throws IOException
	{
		// Extract the PemObject (metadata) and Key Pair (hopefully) from the file
		PEMParser parser = new PEMParser( new FileReader(file) );
		Object temp = parser.readObject();
		parser.close();

		if( temp instanceof SubjectPublicKeyInfo )
		{
			SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo)temp;
			return new JcaPEMKeyConverter().getPublicKey( publicKeyInfo );
		}
		
		// We don't know what we read...
		throw new JConfigurationException( "Public Key load error: Unsupported ("+temp.getClass()+")" );
	}


	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
	public static void main( String[] args ) throws Exception
	{
		new CryptoRsaTest().run();
	}
}
