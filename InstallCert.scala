/*
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import java.io._;
import java.net.URL;

import java.security._;
import java.security.cert._;

import javax.net.ssl._;

/** 
 * This class downloads the certificates from the server in the argument and offers to install the certificate into the
 * trusted keystore.  I think the default keystore is ~/.keystore.  
 *
 * This is required so that security-proxy can talk to a cas that does not have a certificate from a trusted Certificate
 * Authority.  This is always the case when testing.  In deployment this should not be required normally.
 * 
 * You will want to set the trust store of the server to point to that keystore file:
 * -Djavax.net.ssl.trustStore=pathToFile
 */
final val Usage = "Usage: java InstallCert <host>[:port] [passphrase]"
private final val HEXDIGITS = "0123456789abcdef".toCharArray();

def toHexString(bytes:Array[Byte]) {
  val sb = new StringBuilder(bytes.length * 3);
 	for (i <- bytes) {
    	val b = i & 0xff;
     sb.append(HEXDIGITS(b >> 4));
     sb.append(HEXDIGITS(b & 15));
     sb.append(' ');
 	}
	sb.toString();
 }

class SavingTrustManager(val tm:X509TrustManager) extends X509TrustManager {

  var chain:Array[X509Certificate] = _;


   def getAcceptedIssuers():Array[X509Certificate] = {
     throw new UnsupportedOperationException()
  	}

 	def checkClientTrusted(chain:Array[X509Certificate], authType:String):Unit = {
   	throw new UnsupportedOperationException();
	}

 	def checkServerTrusted(chain:Array[X509Certificate], authType:String):Unit = {
   	this.chain = chain;
 		tm.checkServerTrusted(chain, authType);
	}
}

var host:String = "";
var port:Int = 80;
var passphrase:Array[Char] = "changeit".toCharArray;
if ((args.length == 1) || (args.length == 2)) {
    val c = args(0).split(":");
    host = c(0);
    port = if (c.length == 1) 443 else Integer.parseInt(c(1));
    val p = if (args.length == 1) "changeit" else args(1);
    passphrase = p.toCharArray();
} else {
  println(Usage);
	exit(0)
}

import File.{separatorChar => SEP}

val outFile = new File(System.getProperty("user.home") + SEP + ".trustStore");
var file = outFile;

if (file.isFile() == false) {
 	val dir = new File(System.getProperty("java.home") + SEP
                        + "lib" + SEP + "security");
  file = new File(dir, "jssecacerts");
  if (file.isFile() == false) {
      file = new File(dir, "cacerts");
  }
}

println("Output KeyStore " + outFile + "...");
println("Loading KeyStore " + file + "...");
val in = new FileInputStream(file);
val ks = KeyStore.getInstance(KeyStore.getDefaultType());
ks.load(in, passphrase);
in.close();

val context = SSLContext.getInstance("TLS");
val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
tmf.init(ks);
val defaultTrustManager = tmf.getTrustManagers()(0).asInstanceOf[X509TrustManager];
val tm = new SavingTrustManager(defaultTrustManager);
context.init(null, Array(tm), null);
val factory = context.getSocketFactory();

println("Opening connection to " + host + ":" + port + "...");
val socket = factory.createSocket(host, port).asInstanceOf[SSLSocket];
socket.setSoTimeout(10000);
try {
	println("Starting SSL handshake...")
	socket.startHandshake();
	socket.close();
	println();
	println("No errors, certificate is already trusted");
} catch {
	case e : SSLException =>
    System.out.println()
    e.printStackTrace(System.out)
}

val chain = tm.chain;
if (chain == null) {
	println("Could not obtain server certificate chain");
  exit(1)
}

val reader = new BufferedReader(new InputStreamReader(System.in));

println();
println("Server sent " + chain.length + " certificate(s):");
println();
val sha1 = MessageDigest.getInstance("SHA1");
val md5 = MessageDigest.getInstance("MD5");
for (i <- 0 to chain.length - 1) {
  val cert = chain(i);
  println (" " + (i + 1) + " Subject " + cert.getSubjectDN());
  println ("   Issuer  " + cert.getIssuerDN());
  sha1.update(cert.getEncoded());
  println ("   sha1    " + toHexString(sha1.digest()));
  md5.update(cert.getEncoded());
  println ("   md5     " + toHexString(md5.digest()));
  println ();
}

println ("Enter certificate to add to trusted keystore or 'q' to quit: [1]");
val line = reader.readLine().trim();
var k:Int = 0;
try {
    k = if (line.length() == 0) 0 else line.toInt - 1;
} catch {
	case _:NumberFormatException => 
    println("KeyStore not changed");
		exit(0)
}

val cert = chain(k);
val alias = host + "-" + (k + 1);
ks.setCertificateEntry(alias, cert);

val out = new FileOutputStream(outFile);
ks.store(out, passphrase);
out.close();

println();
println(cert);
println();
println ("Added certificate to keystore '"+file+"' using alias '" + alias + "'");

