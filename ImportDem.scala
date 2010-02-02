
import java.security._
import java.io.IOException;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.DataInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.security.spec._;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Iterator;

/**
 * 
 * <p>This class imports a key and a certificate into a keystore
 * (<code>$home/keystore.ImportKey</code>). If the keystore is
 * already present, it is simply deleted. Both the key and the
 * certificate file must be in <code>DER</code>-format. The key must be
 * encoded with <code>PKCS#8</code>-format. The certificate must be
 * encoded in <code>X.509</code>-format.</p>
 *
 * <p>Key format:</p>
 * <p><code>openssl pkcs8 -topk8 -nocrypt -in YOUR.KEY -out YOUR.KEY.der
 * -outform der</code></p>
 * <p>Format of the certificate:</p>
 * <p><code>openssl x509 -in YOUR.CERT -out YOUR.CERT.der -outform
 * der</code></p>
 * <p>Import key and certificate:</p>
 * <p><code>java comu.ImportKey YOUR.KEY.der YOUR.CERT.der</code></p><br />
 *
 * <em>Note:</em> If you just need to import a trust certificate then you can just
 * use keytool to import it after using openssl to convert it to dem format:
 * <p><code>keytool -import -keystore cacerts -file unhcr.cert -alias prod-unhcr.camptocamp.net -trustcacerts</code></p>
 * 
 * <p><em>Caution:</em> the old <code>keystore.ImportKey</code>-file is
 * deleted and replaced with a keystore only containing <code>YOUR.KEY</code>
 * and <code>YOUR.CERT</code>. The keystore and the key has no password; 
 * they can be set by the <code>keytool -keypasswd</code>-command for setting
 * the key password, and the <code>keytool -storepasswd</code>-command to set
 * the keystore password.
 * <p>The key and the certificate is stored under the alias
 * <code>importkey</code>; to change this, use <code>keytool -keyclone</code>.
 *
 * Created: Fri Apr 13 18:15:07 2001
 * Updated: Fri Apr 19 11:03:00 2002
 *
 * @author Joachim Karrer, Jens Carlberg
 * @version 1.1
 **/
object ImportDem  {
    
    /**
     * <p>Creates an InputStream from a file, and fills it with the complete
     * file. Thus, available() on the returned InputStream will return the
     * full number of bytes the file contains</p>
     * @param fname The filename
     * @return The filled InputStream
     * @exception IOException, if the Streams couldn't be created.
     **/
    def fullStream ( fname:String ):InputStream = {
        val fis = new FileInputStream(fname);
        val dis = new DataInputStream(fis);
        val bytes = new Array[Byte](dis.available());
        dis.readFully(bytes);

        val bais = new ByteArrayInputStream(bytes);
        return bais;
    }
        
    /**
     * <p>Takes two file names for a key and the certificate for the key, 
     * and imports those into a keystore. Optionally it takes an alias
     * for the key.
     * <p>The first argument is the filename for the key. The key should be
     * in PKCS8-format.
     * <p>The second argument is the filename for the certificate for the key.
     * <p>If a third argument is given it is used as the alias. If missing,
     * the key is imported with the alias importkey
     * <p>The name of the keystore file can be controlled by setting
     * the keystore property (java -Dkeystore=mykeystore). If no name
     * is given, the file is named <code>keystore.ImportKey</code>
     * and placed in your home directory.
     * @param args (0) Name of the key file, (1) Name of the certificate file
     * (2) Alias for the key.
     **/
    final def main (args:Array[String]) {
        // change this if you want another password by default
        val keypass = "importkey";
        
        // change this if you want another alias by default
        var defaultalias = "importkey";

        // change this if you want another keystorefile by default
        val keystorename = 
          if (System.getProperty("keystore") == null) {
            System.getProperty("user.home")+
              System.getProperty("file.separator")+
              "keystore.ImportKey"; // especially this ;-)
          } else {
            System.getProperty("keystore");
          }

        // parsing command line input
        var keyfile = "";
        var certfile = "";
        if (args.length < 2 || args.length>3) {
            println("Usage: scala ImportDem.scala keyfile certfile [alias]");
            exit(0);
        } else {
            keyfile = args(0);
            certfile = args(1);
            if (args.length>2)
                defaultalias = args(2);
        }

        try {
            // initializing and clearing keystore 
            val ks = KeyStore.getInstance("JKS", "SUN");
            ks.load( null , keypass.toCharArray());
            println("Using keystore-file : "+keystorename);
            ks.store(new FileOutputStream ( keystorename  ),
                    keypass.toCharArray());
            ks.load(new FileInputStream ( keystorename ),
                    keypass.toCharArray());

            // loading Key
            val fl = fullStream (keyfile);
            val key = new Array[Byte](fl.available());
            val kf = KeyFactory.getInstance("RSA");

            fl.read ( key, 0, fl.available() );
            fl.close();
            val keysp = new PKCS8EncodedKeySpec ( key );
            val ff = kf.generatePrivate (keysp);

            // loading CertificateChain
            val cf = CertificateFactory.getInstance("X.509");
            var certstream = fullStream (certfile);

            val c = cf.generateCertificates(certstream) ;
            var certs = new Array[Certificate](c.toArray().length);

            if (c.size() == 1) {
                certstream = fullStream (certfile);
                System.out.println("One certificate, no chain.");
                val cert = cf.generateCertificate(certstream) ;
                certs(0) = cert;
            } else {
                System.out.println("Certificate chain length: "+c.size());
                certs = c.toArray().asInstanceOf[Array[Certificate]];
            }

            // storing keystore
            ks.setKeyEntry(defaultalias, ff, 
                           keypass.toCharArray(),
                           certs );
            println ("Key and certificate stored.");
            println ("Alias:"+defaultalias+"  Password:"+keypass);
            ks.store(new FileOutputStream ( keystorename ),
                     keypass.toCharArray());
        } catch {
            case ex => ex.printStackTrace();
        }
    }

}// ImportDem

ImportDem.main(args)
