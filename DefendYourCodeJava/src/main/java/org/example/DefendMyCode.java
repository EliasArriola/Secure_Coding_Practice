package org.example;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class DefendMyCode {

    private static final int MAX_ATTEMPTS = 3;

    private static final Scanner INPUT_SCANNER = new Scanner(System.in);
    private static final String PASSWORD_FILE_NAME = "HASHED_PASSWORD";
    private static final Logger LOGGER = Logger.getLogger(DefendMyCode.class.getName());
    private static String INPUT_FILE_NAME = "";

    public static void main(String[] args) {
        if (initLogger()) {
            String[] userNames = getValidatedName();
            int int1 = getInteger(1);
            int int2 = getInteger(2);
            long[] addMultiplyResult = addMultiplyTwoIntegers(int1, int2);
            INPUT_FILE_NAME = getFileName(true, "input");
            String outputFilename = getFileName(false, "output");
            getAndVerifyPassword();
            writeOutput(outputFilename, userNames, int1, int2, addMultiplyResult, INPUT_FILE_NAME);
        }
    }

    private static boolean initLogger() {
        FileHandler fh;
        boolean initializeCorrectly = false;
        try {
            fh = new FileHandler("./LOGGER");
            LOGGER.addHandler(fh);
            SimpleFormatter formatter = new SimpleFormatter();
            fh.setFormatter(formatter);
            initializeCorrectly = true;
        } catch (SecurityException | IOException e) {
            System.out.println("Logger Failed to Initialize. Please Try Again.");
        }
        return initializeCorrectly;
    }

    private static String[] getValidatedName() {
        String firstName, lastName;

        while (true) {
            System.out.println("First and last name should be a maximum of 50 characters each.");
            System.out.println("Only one capital letter at the beginning is allowed.");
            System.out.println("After first capital, only letters a-z permitted.");
            System.out.print("Enter first name: ");
            firstName = INPUT_SCANNER.nextLine();
            System.out.print("Enter last name: ");
            lastName = INPUT_SCANNER.nextLine();
            if (verifyName(firstName) && verifyName(lastName)) {
                return new String[]{ firstName, lastName };
            } else {
                System.out.println("Invalid name format! Please try again.");
            }
        }
    }

    public static boolean verifyName(String name) {
        String pattern = "^[A-Z][a-z]{1,49}$";
        return name.matches(pattern);
    }

    private static int getInteger(int num) {
        while (true) {
            System.out.println("Valid integers are in range -2147483648 to 2147483647");
            System.out.printf("Enter integer #%d: ", num);
            String line = INPUT_SCANNER.nextLine();
            Scanner scLine = new Scanner(line);
            if (scLine.hasNext()) {
                String enteredInt = scLine.next();
                if (validateInteger(enteredInt)) {
                    try {
                        return Integer.parseInt(enteredInt);
                    } catch (NumberFormatException ignored) {

                    }
                }
            }
            System.out.println("Invalid integer! Please try again.");
        }
    }

    public static boolean validateInteger(String input) {
        String pattern = "^0$|^-?([1-9][0-9]{0,9})$";
        return input.matches(pattern);
    }

    public static long[] addMultiplyTwoIntegers(int num1, int num2) {
        return new long[]{(long) num1 + (long) num2, (long) num1 * (long) num2};
    }

    private static String getFileName(boolean checkIfFileExists, String type) {
        while (true) {
            System.out.println("Valid filenames length must be between 1 and 50 characters. And end with a .txt extension");
            System.out.printf("Enter a valid %s filename: ", type);
            String line = INPUT_SCANNER.nextLine();
            Scanner scLine = new Scanner(line);
            if (scLine.hasNext()) {
                String enteredFileName = scLine.next();
                if (validateFileName(enteredFileName)) {
                    File file = new File(enteredFileName);
                    if(type.equals("input")) {
                        if (!checkIfFileExists || file.exists()) {
                            return enteredFileName;
                        }
                    } else if (type.equals("output")) {
                        if(enteredFileName.equals(INPUT_FILE_NAME)) {
                            continue;
                        } else {
                            if (!checkIfFileExists || file.exists()) {
                                return enteredFileName;
                            }
                        }
                    }
                }
            }
            System.out.println("Invalid filename! Please try again.");
        }
    }

    public static boolean validateFileName(String fileName) {
        String pattern = "^[A-Za-z0-9]{1,50}.txt$";
        return fileName.matches(pattern);
    }

    private static void getAndVerifyPassword() {
        boolean matchingPassword = false;
        while (!matchingPassword) {
            getHashedPassword();
            matchingPassword = verifyPassword();
        }
    }

    private static void getHashedPassword() {
        boolean validPasswordWritten = false;
        while (!validPasswordWritten) {
            System.out.println("Valid password: At least one uppercase, one lowercase, one digit, one special character(?!,:;-{}()[]'\"), and is at least 10 characters long.");
            System.out.print("Enter valid password: ");
            String line = INPUT_SCANNER.nextLine();
            Scanner scLine = new Scanner(line);
            if (scLine.hasNext()) {
                String enteredPassword = scLine.next();
                if (checkAndWritePassword(enteredPassword)) {
                    validPasswordWritten = true;
                } else {
                    System.out.println("Invalid Password! Please try again.");
                }
            }
        }
    }

    public static boolean checkAndWritePassword(String enteredPassword) {
        String pattern = "^(?=.*[A-Z])(?=.*\\d)(?=.*[a-z])(?=.*[?!,:;\\-{}()\\[\\]'\"])(?!.*[a-z]{4})[A-Z\\da-z?!,:;\\-{}()\\[\\]'\"]{10,}";
        boolean result = false;
        if (enteredPassword != null && enteredPassword.matches(pattern)) {

            // Argon2 library takes care of salting for us.
            // https://docs.spring.io/spring-security/reference/api/java/org/springframework/security/crypto/argon2/Argon2PasswordEncoder.html#defaultsForSpringSecurity_v5_8()
            Argon2PasswordEncoder arg2Encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

            String hashedPassword = arg2Encoder.encode(enteredPassword);

            File hashedPasswordFile = new File(PASSWORD_FILE_NAME);
            try {
                hashedPasswordFile.createNewFile();
                FileWriter hashedPasswordFileWriter = new FileWriter(hashedPasswordFile);
                hashedPasswordFileWriter.write(hashedPassword);
                hashedPasswordFileWriter.close();
                result = true;
            } catch (IOException e) {
                LOGGER.info(e.getMessage());
            }
        }
        return result;
    }

    private static boolean verifyPassword() {
        boolean matchingPassword = false;
        boolean fileOk = false;
        Scanner hashedPasswordScanner = null;
        try {
            hashedPasswordScanner = new Scanner(new File(PASSWORD_FILE_NAME));
            fileOk = true;
        } catch (FileNotFoundException e) {
            LOGGER.info(e.getMessage());
        }
        if (fileOk && hashedPasswordScanner.hasNext()) {
            String hashedPassword = hashedPasswordScanner.next();
            int confirmedAttempts = 0;
            while (!matchingPassword && confirmedAttempts < MAX_ATTEMPTS) {
                System.out.print("Confirm password: ");
                String line = INPUT_SCANNER.nextLine();
                Scanner scLine = new Scanner(line);
                if (scLine.hasNext()) {
                    String enteredPassword = scLine.next();
                    if (validatePasswordMatches(enteredPassword, hashedPassword)) {
                        matchingPassword = true;
                    } else {
                        System.out.println("Invalid Password! Please try again.");
                        confirmedAttempts++;
                    }
                }
            }
        }
        return matchingPassword;
    }

    public static boolean validatePasswordMatches(String enteredPassword, String hashedPassword) {
        boolean isValidPassword = false;
        if (enteredPassword != null && hashedPassword != null) {
            Argon2PasswordEncoder arg2Encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
            isValidPassword = arg2Encoder.matches(enteredPassword, hashedPassword);
        }
        return isValidPassword;
    }

    private static void writeOutput(String outputFilename, String[] userNames, int int1, int int2, long[] addMultiplyResult, String inputFileName) {

        File outputFile = new File(outputFilename);
        try {
            outputFile.createNewFile();
            FileWriter fw = new FileWriter(outputFile);
            fw.write("First Name: " + userNames[0] + "\n");
            fw.write("Last Name: " + userNames[1] + "\n");
            fw.write("Integer #1: " + int1 + "\n");
            fw.write("Integer #2: " + int2 + "\n");
            fw.write("Adding Result: " + addMultiplyResult[0] + "\n");
            fw.write("Multiply Result: " + addMultiplyResult[1] + "\n");
            fw.write("Input File Contents:\n");
            writeInputToOutput(fw, inputFileName);
            fw.close();
        } catch (IOException e) {
            LOGGER.info(e.getMessage());
        }
    }

    private static void writeInputToOutput(FileWriter fw, String inputFileName) {
        try {
            Scanner scLine = new Scanner(new File(inputFileName));
            while (scLine.hasNextLine()) {
                fw.write(scLine.nextLine() + "\n");
            }
        } catch (IOException e) {
            LOGGER.info(e.getMessage());
        }
    }
}