import java.security.SecureRandom;
import java.util.Random;

public class PasswordGenerator {

    //Different sets of characters in lists to make sure that for the
    //different character types are accounted for

    //List of all lower case letters (a to z)
    static final Character[] LowerCaseLetters = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
    //List of all upper case letters (A to Z)
    static final Character[]  UpperCaseLetters = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
    //List of all numbers (0 to 9)
    static final Character[] Numbers = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    //A list of all special symbols allowed
    static final Character[]  SpecialSymbols  = {'!', '@', '#', '$', '%', '^', '&', '/', '?', '<', '>', '*', '(', ')', '+', '_'};

    //Uses SecureRandom for performing random password generation
    private SecureRandom rand = new SecureRandom();

    //Stores the password being created
    String generatedPassword = "";

    //Stores a string builder for creating the password
    StringBuilder passwSB;
    //A method for allowing a password to be created, accepts a int which
    //determines the length in characters of the password being created
    public String CreatePassword(int Length) {
        //Initialises the string builder
        passwSB = new StringBuilder();
        //Used to be able to store the character which is being added to the string
        //builder
        char character = '*';

        //Checks if the password length is greater or equal to 8 and less than or equal to 80
        if (Length < 8 && Length <= 80) {
            //If out of the range, let the user know
            System.out.println("");
            System.out.println("Error! Password length must be between 8 and 80 characters long");
            //Quits the program
            System.exit(0);
        }
        //Loops through each the length in order to cover all the characters
        for(int i = 0; i < Length; i++) {
            //Creates a random int for selecting one of the 4 banks for chars
            int type = rand.nextInt(4);
            //A int for storing the index into the character arrays
            int CharIndex = 0;
            //For each of the different cases, assign the symbol being added as the given character

            //If the type is for Lower or Upper case (0 or 1)
            if(type == 0 || type == 1){
                //Generates a random number for picking a index into the Upper / Lower character array
                CharIndex = rand.nextInt(LowerCaseLetters.length);
                //Checks if type is 0 or 1
                if(type == 0){
                    character = LowerCaseLetters[CharIndex];
                }
                else if(type == 1){
                    character = UpperCaseLetters[CharIndex];
                }
            }
            //Else if the type is for numbers (2)
            else if(type == 2){
                //Generates a random number for picking a index into the number character array
                CharIndex = rand.nextInt(Numbers.length);
                character = Numbers[CharIndex];
            }
            //Else if the type is for special characters (3)
            else if(type == 3){
                //Generates a random number for picking a index into the specialSymbols character array
                CharIndex = rand.nextInt(SpecialSymbols.length);
                character = SpecialSymbols[CharIndex];
            }
            //Adds the chosen character to the string builder
            passwSB.append(character);
        }
        //Returns the password from the string builder
        return passwSB.toString();
    }
}
