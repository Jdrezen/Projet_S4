package myBlockChain;

import java.util.Scanner;
import java.io.IOException;

public class Interface {
	private String choice;
	
	/**
	 * Lance l'interface graphique
	 */
	public void affichage() throws IOException {
		BlockChain BlockC;
		Scanner sc = new Scanner(System.in);
		System.out.println("Que voulez vous faire ?\n");
		System.out.println("1: Générer une blockchain");
		System.out.println("2: Lire une blockchain");
		
		choice = sc.nextLine();
		
		if(choice.equals("1")) {
			BlockC = generateBlockChain(sc);
		}
		else {
			BlockC = BCJsonUtils.BCJsonReader(getFileName(sc));
		}
		
		sc.nextLine();
		
		while(true) {
			allChoices();
			choice = sc.nextLine();
			System.out.println("Vous avez saisi : " + choice + "\n");
			switch(choice)
	        {
	            case "1" :
	                BlockC = generateBlockChain(sc);
	            break;
	            
	            case "2" :
	            	BCJsonUtils.BCJsonWriter(BlockC, getFileName(sc));
	            break;
	            
	            case "3" :
	            	BlockC = BCJsonUtils.BCJsonReader(getFileName(sc));
	            break;
	            
	            case "4" :
	            	if(BlockC.verifIntegrity()) {
	            		System.out.println("La BlockChain est validée");
	            	}
	            	else {
	            		System.out.println("La BlockChain n'est pas vérifiée");
	            	}
	            break;
	            
	            case "5" :
	            	BlockC.printBlockChain();
	            break;
	            
	            case "6" :
	            	printBlockBlockChain(sc, BlockC);
	            break;
	            
	            case "7" :
	            	if(BlockC.getLastBlock().addTransaction("TxEnAttente.txt") == false) {
	            		if(BlockC.ajoutBlock() == true) {
	            			BlockC.getLastBlock().addTransaction("TxEnAttente.txt");
	            		}
	            	}
	            	
	            break;
	            
	            case "8" :
	            	System.out.println(BlockC.searchOwner(getKey(sc)));
	            break;
	            
	            case "9" :
	            	System.out.println(BlockC.searchKeys(getOwner(sc)));
	            break;
	            
	            case "10" :
	            	System.out.println(BlockC.stateKey(getKey(sc)));
	            break;
	            
	            case "11" :
	            	if(historicOwner(sc) == true) {
	            		System.out.println(BlockC.historic(getOwner(sc),true));
	            	}
	            	else {
	            		System.out.println(BlockC.historic(getKey(sc),false));
	            	}
	            break;
	            
	            case "12" :
	                System.out.println("Vous nous quittez déjà, quelle dommage\n");
	                System.exit(0);
	                
	            default:
	                System.out.println("Vous n'avez pas saisi un choix valide\n");
	            break;
	        }
		}
	}
	
	/**
	 * Affichage les differents choix pour exécuter le programme
	 */
	public void allChoices() {
		System.out.println("Que voulez vous faire avec le programme ? \n");
		System.out.println("1: Générer une nouvelle blockchain");
		System.out.println("2: Sauvegarder dans un fichier");
		System.out.println("3: Lire une nouvelle blockchain");
		System.out.println("4: Vérifier l'intégrité de la blockchain");
		System.out.println("5: Afficher la blockchain");
		System.out.println("6: Afficher un block de la blockchain");
		System.out.println("7: Intégrer une transaction dans la blockChain");
		System.out.println("8: Trouver le propriétaire d'une clé");
		System.out.println("9: Afficher toutes les clés d'une personne");
		System.out.println("10: Connaître l'état d'une clé");
		System.out.println("11: Connaître l'historique d'une clé/personne");
		System.out.println("12: Quitter le programme");
		System.out.println("Que voulez vous faire :");
	}
	
	/**
	 * @param sc le scanner permettant de saisir les données
	 * @return la blockchain générée
	 */
	public BlockChain generateBlockChain(Scanner sc) {
		BlockChain blockChain;
		int nbBlock, complexity, nbTransactions;
		
		System.out.println("Veuillez choisir le nombre de bloc :");
		nbBlock = sc.nextInt();
		System.out.println("Vous avez saisi : " + nbBlock);
		
		System.out.println("Veuillez choisir la complexité :");
		complexity = sc.nextInt();
		System.out.println("Vous avez saisi : " + complexity);
		
		System.out.println("Veuillez choisir le nombre transaction max par bloc :");
		nbTransactions = sc.nextInt();
		System.out.println("Vous avez saisi : \n" + nbTransactions + "\n");
		
		blockChain = new BlockChain(complexity, nbBlock, nbTransactions);
		
		return blockChain;
		
	}
	
	/**
	 * Affiche un block de la blockchain
	 * @param sc le scanner permettant de saisir les données
	 * @param blockC la blockchain
	 */
	public void printBlockBlockChain(Scanner sc, BlockChain blockC) {
		int num;
		System.out.println("Veuillez choisir le numéro de bloc :");
		num = sc.nextInt();
		System.out.println("Vous avez saisi : " + num);
		if(num == 0)
			blockC.getBlock(num).printFirstBlock();
		else
			blockC.getBlock(num).printBlock();
		sc.nextLine();
	}
	
	/**
	 * @param sc le scanner permettant de saisir les données
	 * @return le nom du fichier saisi
	 */
	public String getFileName(Scanner sc) {
		System.out.println("Veuillez choisir le fichier :");
		
		return (sc.nextLine());
	}
	
	/**
	 * @param sc le scanner permettant de saisir les données
	 * @return la clé saisie
	 */
	public String getKey(Scanner sc) {
		String e,n;
		System.out.println("Veuillez saisir la première partie de la clé :");
		e = sc.nextLine();
		System.out.println("Veuillez saisir la deuxième partie de la clé :");
		n = sc.nextLine();
		return("(" + e + " , " + n + ")");
	}
	
	/**
	 * @param sc le scanner permettant de saisir les données
	 * @return le mail du propriétaire saisi
	 */
	public String getOwner(Scanner sc) {
		System.out.println("Veuillez saisir l'adresse mail de la personne :");
		return sc.nextLine();
	}
	
	/**
	 * @param sc le scanner permettant de saisir les données
	 * @return vrai si l'historique est pour un propriétaire, faux si c'est pour une clé
	 */
	public boolean historicOwner(Scanner sc) {
		System.out.println("Pour qui voulez vous l'historique ?\n");
		System.out.println("1: Pour une clé");
		System.out.println("2: Pour une personne");
		return (sc.nextLine().equals("2"));
	}
	
} 
