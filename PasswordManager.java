import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.NoSuchProviderException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

public class PasswordManager {
  private Scanner sc;
  //The main method for the program, runs the userOptions screen
  //to allow for a user to pick what they want to do
  public static void main(String[] args) {
      try{
          PasswordManager pm = new PasswordManager();
          pm.userOptions();
      }
      catch(InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | BadPaddingException | NoSuchPaddingException |
      IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidParameterSpecException | InvalidKeySpecException | IOException e){
          //Prints out the exception message
          System.out.println(e.getMessage());
      }
  }
  //A method which provides users with a list of options which they can choose
  //from in order to perform the various functions of the program
  public void userOptions() throws
          InvalidKeyException,NoSuchProviderException,IOException,NoSuchPaddingException,
          NoSuchAlgorithmException,IllegalBlockSizeException,
          BadPaddingException,InvalidParameterSpecException,InvalidKeySpecException,
          InvalidAlgorithmParameterException {
      //If that correctly passes, then create instances of the modules which
      //are utilised for the ADD, GET and DEL (Password Storage, Password Retriever)
      PasswordRetriever pr = new PasswordRetriever();
      PasswordStorage ps = new PasswordStorage();
      //Goes through a infinite loop until the program exits (User chooses the
      //EXIT option)
      while(true){
        //Stores the option chosen by a user
        String func = "";
        //Sets up a scanner for reading in a users input
        sc = new Scanner(System.in);
        //Loops through until func is assigned a correct command
        while (func.equals("")){
            //Prints out the instructions for the user to select from
            System.out.println("");
            System.out.println("ADD : For storing a new password for a given application name");
            System.out.println("GET : For retrieving a saved password for a given application name");
            System.out.println("DEL : For removing a saved password for a given application name");
            System.out.println("QUIT : For exiting the Password Manager");
            System.out.println("");
            System.out.println("Choose an option from the set given of commands");
            //Once a user has entered input and pressed the enter key
            String userInput = sc.nextLine().toUpperCase();
            //If the value entered is not under the given
            if((userInput.equals("ADD") || userInput.equals("GET") || userInput.equals("DEL") || userInput.equals("QUIT")) != true){
                System.out.println("Error! " + userInput + " is not a valid input!");
            }
            //If one of the correct inputs, then assign the func to the be user input
            else{
              //Assigns funct to the user input value
              func = userInput;
            }
        }
        //Once assigned a correct value, check which function to perform and
        //call the assiciated method
        if(func.equals("ADD")){
          ps.registerAppPassword();
        }
        else if(func.equals("GET")){
          pr.getPassword();
        }
        else if(func.equals("DEL")){
          ps.deleteAppPassword();
        }
        else if(func.equals("QUIT")){
          System.exit(0);
        }
      }
  }
}
