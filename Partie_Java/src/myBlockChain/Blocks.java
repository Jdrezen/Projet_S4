package myBlockChain;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;


/**
 * @author drezenjeremie
 *
 */
public class Blocks {
	private int index;
	private String timestamp;
	private String hashPrevious;
	private String hashRoot;
	private String hashCurrent;
	private int nbTransactions;
	private Transactions[] listTransactions;
	private int nonce;
	
	public Blocks(int numero, int nbTransactionsMax) {
		this.index = numero;
		timestamp = getDate();
		hashPrevious = new String("");
		nbTransactions = 0;
		listTransactions = new Transactions[(Math.abs(new Random().nextInt()) % nbTransactionsMax) + 1];
		hashCurrent = new String("Block non complet");
		nonce = 0;
	}
	
	/**
	 * Retourne la date actuelle sous la forme "jour-mois-année"
	 * @return la date actuelle
	 */
	public static String getDate() {
	       final Date date = new Date();
	       return new SimpleDateFormat("dd-MM-yyyy").format(date);
	}
	
	public void setHashPrevious(String hash) {
		this.hashPrevious = hash;
	}
	
	public String getHashPrevious() {
		return hashPrevious;
	}
	
	public String getHashCurrent() {
		return hashCurrent;
	}
	
	public String getHashRoot() {
		return hashRoot;
	}
	
	public int getNbTransactions() {
		return nbTransactions;
	}
	
	public Transactions[] getListTransactions() {
		return listTransactions;
	}
	
	/**
	 * @return vrai si le bloc est complet
	 */
	public boolean isComplete() {
		return (nbTransactions == listTransactions.length);
	}

	
	/**
	 * Réalise un minage sur le block
	 * @param complexity la complexité du block
	 */
	public void minage(int complexity) {
		hashRoot = hashBlock();
		String hash = hashRoot;
		String test  = hash.substring(0,complexity);
		String difficulty = "";
		
		for(int i = 0; i < complexity; i++) {
			difficulty = difficulty + "0";
		}
		
		while(!test.equals(difficulty)) {
			hash = hash + nonce;
			
			hash  = HashUtil.applySha256(hash);
			
			test  = hash.substring(0,complexity);
			nonce++;
		}
		hashCurrent = hash;
	}
	
	/**
	 * Retourne la hashRoot du block en utilisant la méthode recursive hashRoot 
	 * @return le hash du block avant minage
	 */
	public String hashBlock(){
		String [] hashTransactions;
		hashTransactions = new String[nbTransactions];
		
		for(int i = 0; i < nbTransactions; i++) {
			hashTransactions[i] = listTransactions[i].hashTransaction();
		}
		return 	hashRoot(hashTransactions, 0, nbTransactions);
	}
	
	/**
	 * Méthode recursive qui calcule la hashRoot du block
	 * @param arbre le tableau des hash des transactions du block
	 * @param deb le début du tableau
	 * @param fin la fin du tableau
	 * @return le hash du block avant minage
	 */
	public static String hashRoot(String[] arbre, int deb, int fin) {
		int milieu;
		if(deb < fin) {
			milieu = (deb+fin) / 2;
			hashRoot(arbre, deb, milieu);
			hashRoot(arbre, milieu + 1, fin);
			concatenation(arbre, deb, fin);
		}
		return arbre[0];
	}
	
	public static void concatenation(String[] arbre, int deb, int fin) {
		for(int i = deb + 1; i < fin; i++) {
			arbre[deb] += arbre[i];
			arbre[i] = "";
		}
		arbre[deb] = HashUtil.applySha256(arbre[deb]);
	}
	
	/**
	 * Initialise le premier block avec des transactions "bidons"
	 */
	public void initFirstBlock() {
		listTransactions[0] = new Transactions(0,"Genesis");
		nbTransactions ++;
	}

	/**
	 * Ajoute des transactions au block, retourne faux si ce n'est plus possible
	 * @param fileName le nom du fichier où se trouve la transaction
	 * @return vrai si la transaction peut être ajouter, faux sinon
	 */
	public boolean addTransaction(String fileName) throws IOException {
		
		if(isComplete() == true) {
			System.out.println("Le bloc est complet");
			return false;
		}
		
		SendMail mail = new SendMail();
		File input = new File(fileName);
		File tempFile = new File("temp.txt");
		BufferedReader lecteurAvecBuffer = null;
		String[] infos = new String[5];
		String line;
		String message;

	    try
	      {
		lecteurAvecBuffer = new BufferedReader(new FileReader(fileName));
	      }
	    catch(FileNotFoundException exc)
	      {
		System.out.println("Erreur d'ouverture");
	      }
	    
	    if(input.length() == 0) {
	    	System.out.println("Le fichier de transaction est vide");
	    	return false;
	    }
	    
	    for (int i = 0; i < 5; i++) {
	    	infos[i] = lecteurAvecBuffer.readLine();
	    	System.out.println(infos[i]);
		}
	    
	    
	    PrintWriter ecrivain = new PrintWriter(new BufferedWriter(new FileWriter(fileName)));
	    
	    while ((line = lecteurAvecBuffer.readLine()) != null) {
	    	ecrivain.println(line);
		}
	    
	    
	    lecteurAvecBuffer.close();
	    ecrivain.close();
	    
	    tempFile.renameTo(input);
	    
	    listTransactions[nbTransactions] = new Transactions(nbTransactions, infos[0], infos[1], infos[2], infos[3], infos[4]);
	    nbTransactions++;
	    
	    if(infos[1].equals("Type CCK")) {
	    	message = "publication de la clé cryptographique";
	    }
	    else if(infos[1].equals("Type RCK")) {
	    	message = "révocation de la clé cryptographique";
	    }
	    else if(infos[1].equals("Type CSK")) {
	    	message = "publication de la clé de signature";
	    }
	    else {
	    	message = "révocation de la clé de signature";
	    }
	    
	    String[] to =  {infos[4]};
		mail.sendFromGMail(to, "[Projet S4] Nouvelle transaction", "La transaction concernant la " + message + " a été acceptée");	
	    return true;
	}
	
	/**
	 * Affiche le premier block 
	 */
	public void printFirstBlock() {
		System.out.println("Block Génésis \nDate création : " + timestamp + "\nHash du précédant : " + hashPrevious + "\nHash du block : " + hashCurrent + "\n");
	}
	
	/**
	 * Affiche le block
	 */
	public void printBlock() {
		System.out.println("Block N° " + index + "\nDate création : " + timestamp + "\nHash du précédant : " + hashPrevious + "\nHash du block : " + hashCurrent);
		System.out.println("Nombre de Transactions : " + nbTransactions + "\nListe des Transactions :");
		for (int i = 0; i < nbTransactions; i++) {
			System.out.println(listTransactions[i].getTransaction());
		}
		System.out.println();
	}
}
