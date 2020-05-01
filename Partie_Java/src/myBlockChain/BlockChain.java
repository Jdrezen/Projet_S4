package myBlockChain;


/**
 * @author drezenjeremie
 *
 */
public class BlockChain {
	private int complexity;
	private int nbBlocks;
	private int nbTransactionsMax;
	private Blocks[] listBlocks;
	
	public BlockChain(int complexity, int nbBlocksMax, int nbTransactionsMax){
		this.complexity = complexity;
		this.nbBlocks = 0;
		this.nbTransactionsMax = nbTransactionsMax;
		this.listBlocks = new Blocks[nbBlocksMax];
		ajoutBlock();
	}
	
	/**
	 * @param numero l'indice du block voulu
	 * @return le block d'indice "numero"
	 */
	public Blocks getBlock(int numero) {
		if(numero < nbBlocks) {
			return listBlocks[numero];
		}
		else {
			System.out.println("Bloc inexistant");
			return getLastBlock();
		}
	}
	
	/**
	 * @return le dernier block de la blockchain
	 */
	public Blocks getLastBlock() {
		return listBlocks[nbBlocks-1]; 
	}
	
	public int getComplexity() {
		return complexity;
	}
	
	
	/**
	 * Ajoute un block à la fin de la blockchain si elle n'est pas complète
	 * @return vrai si l'ajout d'un block est possible, faux sinon
	 */
	public boolean ajoutBlock() {
		if(nbBlocks == listBlocks.length) {
			System.out.println("La blockchain est complète");
			getLastBlock().minage(complexity);
			return false;
		}
		
		if(nbBlocks != 0 && getLastBlock().isComplete() == false) {
			System.out.println("Le dernier bloc de la chaine n'est pas encore complet");
			return false;
		}
		
		if(nbBlocks == 0) {
			listBlocks[0] = new Blocks(0,1);
			listBlocks[0].initFirstBlock();
			listBlocks[0].setHashPrevious("0");
		}
		else {
			listBlocks[nbBlocks] = new Blocks(nbBlocks,nbTransactionsMax);
			getLastBlock().minage(complexity);
			listBlocks[nbBlocks].setHashPrevious(getLastBlock().getHashCurrent());
			
		}
		nbBlocks++;
		System.out.println("Ajout d'un bloc avec succès");
		return true;
		
	}
	
	/**
	 * Vérifie l'intégrité de la blockchain
	 * @return vrai si la blockchain est vérifié
	 */
	public boolean verifIntegrity() {
		/*Test 1*/
		if(hasGenesis() && correctChain() && correctHashRoot()) {
				return true;
		}
		return false;
	}
	
	/**
	 * @return vrai si la blockchain a un bloc Génésis
	 */
	public boolean hasGenesis() {
		if((listBlocks[0].getHashPrevious().compareTo("0") == 0) && (listBlocks[0].getListTransactions()[0].getType().compareTo("Genesis") == 0))
			return true;
		return false;
	}
	
	/**
	 * @return vrai si le chaînage de la blockchain est correct
	 */
	public boolean correctChain() {
		for(int i = 0; i < nbBlocks - 1; i++) {
			if(listBlocks[i+1].getHashPrevious().compareTo(listBlocks[i].getHashCurrent()) != 0)
				return false;
		}
		return true;
	}
	
	/**
	 * @return vrai si les hashRoot correspondent bien aux transactions du block
	 */
	public boolean correctHashRoot() {
		for(int i = 0; i < nbBlocks - 1; i++) {
			if(listBlocks[i].getHashRoot().compareTo(listBlocks[i].hashBlock()) != 0) {
				System.out.println(listBlocks[i].getHashRoot());
				System.out.println(listBlocks[i].hashBlock());
				return false;
			}
		}
		return true;
	}
	
	/**
	 * Affiche toute la blockchain
	 */
	public void printBlockChain(){
		listBlocks[0].printFirstBlock();
		for(int i = 1; i < nbBlocks; i++) {
			listBlocks[i].printBlock();
		}
	}
	
	/**
	 * @param key la clé dont on cherche le propriétaire
	 * @return le  propriétaire de la clé
	 */
	public String searchOwner(String key) {
		for(int i = nbBlocks - 1; i > 0; i--) {
			for(int j = listBlocks[i].getNbTransactions() - 1; j >= 0 ; j--) {
				if(listBlocks[i].getListTransactions()[j].getPublicKey().equals(key) || listBlocks[i].getListTransactions()[j].getVerificationKey().equals(key)) {
					return ("Le propriétaire de la clé " + key + " est " + listBlocks[i].getListTransactions()[j].getMail() + "\n");
				}
			}
		}
		return "Il n'y a pas de propriétaire pour cette clé \n";
	}
	
	/**
	 * @param owner le propriétaire dont on cherche les clés
	 * @return les clés du propriétaire
	 */
	public String searchKeys(String owner) {
		String keys = "";
		Transactions current;
		for(int i = nbBlocks - 1; i > 0; i--) {
			for(int j = listBlocks[i].getNbTransactions() - 1; j >= 0 ; j--) {
				if((current = listBlocks[i].getListTransactions()[j]).getMail().equals(owner)) {
					keys = keys + ("Clé publique " + current.getPublicKey() + "\n" + "Clé de signature " + current.getVerificationKey() + "\n");
				}
			}
		}
		if(keys.equals("")) {
			System.out.println("Il n'y a aucune clé pour le propriétaire " + owner);
			return "";
		}
		else {
			System.out.println("Voici les clés du propriétaire " + owner);
			return keys;
		}
	}
	
	/**
	 * @param key la clé dont cherche l'état
	 * @return l'état de la clé (certify ou revoke)
	 */
	public String stateKey(String key) {
		for(int i = nbBlocks - 1; i > 0; i--) {
			for(int j = listBlocks[i].getNbTransactions() - 1; j >= 0 ; j--) {
				if(listBlocks[i].getListTransactions()[j].getPublicKey().equals(key) || listBlocks[i].getListTransactions()[j].getVerificationKey().equals(key)) {
					return ("La clé " + key + listBlocks[i].getListTransactions()[j].getType() + " par " + listBlocks[i].getListTransactions()[j].getMail() + "\n");
				}
			}
		}
		return "Il n'y a pas de clé " + key + " dans la blockChain \n";
	}
	
	/**
	 * @param object la clé ou le propriétaire dont on souhaite l'historique
	 * @param forOwner vrai si l'historique est pour un propriétaire, faux si c'est pour une clé
	 * @return l'historique de la clé ou du propriétaire
	 */
	public String historic(String object, boolean forOwner) {
		String historic = "";
		Transactions current;
		for(int i = 1; i < nbBlocks; i++) {
			for(int j = 0; j < listBlocks[i].getNbTransactions(); j++) {
				if(forOwner) {
					if((current = listBlocks[i].getListTransactions()[j]).getMail().equals(object)) {
						historic = historic + current.getTransaction() + "\n";
					}
				}
				else {
					if((current = listBlocks[i].getListTransactions()[j]).getPublicKey().equals(object) 
					|| (current = listBlocks[i].getListTransactions()[j]).getVerificationKey().equals(object)){
						
						historic = historic + current.getTransaction() + "\n";
					}
				}
				
			}
		}
		if(historic.equals("")) {
			if(forOwner) {
				System.out.println("Il n'y a rien concernant le propriétaire " + object);
			}
			else {
				System.out.println("Il n'y a rien concernant la clé " + object);
			}
			
			return "";
		}
		else {
			System.out.println("Voici l'historique ");
			return historic;
		}
	}
}