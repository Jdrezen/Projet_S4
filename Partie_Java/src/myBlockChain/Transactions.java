package myBlockChain;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author drezenjeremie
 *
 */
public class Transactions {
	private int index;
	private String type;
	private String timestamp;
	private String mailTransmitter;
	private String publicKey;
	private String verificationKey;
	
	public String getType() {
		if(type.equals("Type CCK")) {
	    	return " cryptographique est vérifié";
	    }
	    else if(type.equals("Type RCK")) {
	    	return " cryptographique est révoqué";
	    }
	    else if(type.equals("Type CSK")) {
	    	return " de signature est vérifié";
	    }
	    else {
	    	return " de signature est révoqué";
	    }
	}
	
	public String getMail() {
		return mailTransmitter;
	}
	
	public String getPublicKey() {
		String[] parts;
		parts = publicKey.split("e ");
		return parts[1];
	}
	
	public String getVerificationKey() {
		String[] parts;
		parts = verificationKey.split("e ");
		return parts[1];
	}
	
	/**
	 * Constructeur pour une transaction plus simple (ex: bloc génésis)
	 * @param indice le numéro de  la transaction dans le block
	 */
	public Transactions (int indice, String type) {
		this.index = indice;
		this.type = type;
		timestamp = getDate();
	}
	
	/**
	 * Constructeur pour créer une transaction complète
	 * @param indice le numéro de la transaction dans le block
	 * @param type le type de la transactions 
	 * @param date la date de création de la transaction
	 * @param publicKey la clé publique de l'utilisateur
	 * @param signKey la clé de signature de l'utilisateur
	 * @param mail le mail de l'utilisateur
	 */
	public Transactions (int indice, String date, String type, String publicKey, String signKey, String mail) {
		this.index = indice;
		timestamp = date;
		this.type = type;
		this.publicKey = publicKey;
		verificationKey = signKey;
		mailTransmitter = mail;
	}
	
	public static String getDate() {
	       final Date date = new Date();
	       return new SimpleDateFormat("dd-MM-yyyy").format(date);
	}
	
	/**
	 * @return le hash de la transaction
	 */
	public String hashTransaction() {
		String hash;
		hash =  HashUtil.applySha256(index + type + timestamp + mailTransmitter + publicKey + verificationKey);
		return hash;
	}
	
	/**
	 * @return la transaction formaté pour un affichage
	 */
	public String getTransaction() {
		return("\t" + type + "\n\t" + timestamp + "\n\t" + mailTransmitter + "\n\t" + publicKey + "\n\t" + verificationKey + "\n");
	}
}
