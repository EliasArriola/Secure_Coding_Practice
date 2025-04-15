package org.example;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

class DefendMyCodeTest {
    private static final DefendMyCode myCodeInstance = new DefendMyCode();

    //addMultiply tests
    @Test
    public void testAddMultiplyWithZero() {
        long[] result = myCodeInstance.addMultiplyTwoIntegers(0, 0);
        assertArrayEquals(new long[]{0, 0}, result);
    }
    //test to make sure no overflow occurs
    @Test
    public void testAddMultiplyEdge1() {
        long[] result = myCodeInstance.addMultiplyTwoIntegers(-2147483648, -2147483648);
        assertArrayEquals(new long[]{-4294967296L, 4611686018427387904L}, result);
    }

    @Test
    public void testAddMultiplyEdge2() {
        long[] result = myCodeInstance.addMultiplyTwoIntegers(2147483647, 2147483647);
        assertArrayEquals(new long[]{4294967294L, 4611686014132420609L}, result);
    }
    @Test
    public void testAddMultiplyEdge3() {
        long[] result = myCodeInstance.addMultiplyTwoIntegers(-2147483648, 2147483647);
        assertArrayEquals(new long[]{-1, -4611686016279904256L}, result);
    }

    //check write password
    //pw
    //valid
    @Test
    public void testValidPasswordBasic() {
        assertTrue(myCodeInstance.checkAndWritePassword("A1b!cDxyz1")); // Meets all criteria
    }

    @Test
    public void testValidPasswordWithDifferentPunctuation() {
        assertTrue(myCodeInstance.checkAndWritePassword("AbC1:xyz!3")); // Uses `:`
    }

    @Test
    public void testValidPasswordWithSquareBrackets() {
        assertTrue(myCodeInstance.checkAndWritePassword("X1yz[]X!abc")); // Uses `[]`
    }

    @Test
    public void testValidPasswordWithCurlyBraces() {
        assertTrue(myCodeInstance.checkAndWritePassword("A9{bD]!xyz")); // Uses `{}` and `]`
    }

    @Test
    public void testValidPasswordWithParentheses() {
        assertTrue(myCodeInstance.checkAndWritePassword("A!1(bCxyz4)")); // Uses `()`
    }

    @Test
    public void testValidPasswordAtMinimumLength() {
        assertTrue(myCodeInstance.checkAndWritePassword("X!1yzAabc-e")); // Exactly 10 characters
    }

    @Test
    public void testValidPasswordWithMaxThreeConsecutiveLowercase() {
        assertTrue(myCodeInstance.checkAndWritePassword("A1abc!Xyz7")); // Exactly 3 lowercase letters in a row
    }

    @Test
    public void testValidPasswordWithHyphen() {
        assertTrue(myCodeInstance.checkAndWritePassword("A1-bCxyz!7")); // Uses `-`
    }

    //Invalid Passwords
    @Test
    public void testInvalidPasswordTooShort() {
        assertFalse(myCodeInstance.checkAndWritePassword("A1b!cD")); // Less than 10 characters
    }

    @Test
    public void testInvalidPasswordMissingUppercase() {
        assertFalse(myCodeInstance.checkAndWritePassword("a1b!cdxyz1")); // No uppercase letter
    }

    @Test
    public void testInvalidPasswordMissingLowercase() {
        assertFalse(myCodeInstance.checkAndWritePassword("A1B!CDXYZ7")); // No lowercase letter
    }

    @Test
    public void testInvalidPasswordMissingDigit() {
        assertFalse(myCodeInstance.checkAndWritePassword("A!bcdXYZpq")); // No digit
    }

    @Test
    public void testInvalidPasswordMissingPunctuation() {
        assertFalse(myCodeInstance.checkAndWritePassword("A1bcdXYZpq")); // No punctuation mark
    }

    @Test
    public void testInvalidPasswordTooManyConsecutiveLowercase() {
        assertFalse(myCodeInstance.checkAndWritePassword("A1bcde!XYZ7")); // More than 3 consecutive lowercase letters
    }

    @Test
    public void testInvalidPasswordWithDisallowedSpecialCharacter() {
        assertFalse(myCodeInstance.checkAndWritePassword("A1bcd@XYZ7")); // `@` is not in allowed punctuation
    }

    @Test
    public void testInvalidPasswordWithOnlyDigitsAndSpecialCharacters() {
        assertFalse(myCodeInstance.checkAndWritePassword("123!@#$%^&*()")); // No letters
    }

    @Test
    public void testInvalidPasswordEmpty() {
        assertFalse(myCodeInstance.checkAndWritePassword("")); // No letters
    }

    //Names
    //VALID
    @Test
    public void testValidFirstName() {
        assertTrue(myCodeInstance.verifyName("Matthew"));
    }

    @Test
    public void testValidLastName() {
        assertTrue(myCodeInstance.verifyName("Uzunoe"));
    }

    //Invalid Names
    @Test
    public void testInvalidNameSpecialChar() {
        assertFalse(myCodeInstance.verifyName("J@hn"));
    }

    @Test
    public void testInvalidNameLowercaseLastName() {
        assertFalse(myCodeInstance.verifyName("smith"));
    }

    @Test
    public void testInvalidNameLowercaseFirstName() {
        assertFalse(myCodeInstance.verifyName("matthew"));
    }

    @Test
    public void testInvalidNameSpace() {
        assertFalse(myCodeInstance.verifyName("Smith "));
    }

    @Test
    public void testInvalidNameSpaceBefore() {
        assertFalse(myCodeInstance.verifyName(" Smith"));
    }

    @Test
    public void testInvalidNameWithDigit() {
        assertFalse(myCodeInstance.verifyName("Sm1th"));
    }

    @Test
    public void testInvalidNameMultipleCaptial() {
        assertFalse(myCodeInstance.verifyName("JoHNNY"));
    }

    @Test
    public void testInvalidNameEmpty() {
        assertFalse(myCodeInstance.verifyName(""));
    }
    @Test
    public void testInvalidNameHyphen() {
        assertFalse(myCodeInstance.verifyName("Uzunoe-Chin"));
    }

    //validate integer
    @Test
    public void testValidIntNegative() {
        assertTrue(myCodeInstance.validateInteger("-1"));
    }
    @Test
    public void testValidInt0() {
        assertTrue(myCodeInstance.validateInteger("0"));
    }
    @Test
    public void testValidIntPositive() {
        assertTrue(myCodeInstance.validateInteger("100"));
    }

    //invalid
    @Test
    public void testEmptyString() {
        assertFalse(myCodeInstance.validateInteger(""));
    }

    @Test
    public void testOnlyNegativeSign() {
        assertFalse(myCodeInstance.validateInteger("-"));
    }

    @Test
    public void testLeadingZeroPositive() {
        assertFalse(myCodeInstance.validateInteger("0123"));
    }

    @Test
    public void testLeadingZeroNegative() {
        assertFalse(myCodeInstance.validateInteger("-0123"));
    }

    @Test
    public void testNonNumericCharacters() {
        assertFalse(myCodeInstance.validateInteger("123abc"));
    }

    @Test
    public void testSpecialCharacters() {
        assertFalse(myCodeInstance.validateInteger("$100"));
    }

    @Test
    public void testTooLargeNumber() {
        assertFalse(myCodeInstance.validateInteger("10000000000"));
    }

    @Test
    public void testWhitespaceInput() {
        assertFalse(myCodeInstance.validateInteger(" 123 "));
    }
    // 5 Valid Test Cases
    @Test
    void testValidFileName_Simple() {
        assertTrue(myCodeInstance.validateFileName("file.txt"), "Expected valid filename.");
    }

    @Test
    void testValidFileName_WithNumbers() {
        assertTrue(myCodeInstance.validateFileName("file123.txt"), "Expected valid filename.");
    }

    @Test
    void testValidFileName_MaxLength() {
        assertTrue(myCodeInstance.validateFileName("a".repeat(46) + ".txt"), "Expected valid filename (50 characters total).");
    }

    @Test
    void testValidFileName_OnlyNumbers() {
        assertTrue(myCodeInstance.validateFileName("1234567890.txt"), "Expected valid filename.");
    }

    @Test
    void testValidFileName_MixedCase() {
        assertTrue(myCodeInstance.validateFileName("FileName123.txt"), "Expected valid filename.");
    }

    // 5 Invalid Test Cases
    @Test
    void testInvalidFileName_MissingExtension() {
        assertFalse(myCodeInstance.validateFileName("file"), "Expected invalid filename (no .txt).");
    }

    @Test
    void testInvalidFileName_SpecialCharacters() {
        assertFalse(myCodeInstance.validateFileName("file@name.txt"), "Expected invalid filename (special character @).");
    }

    @Test
    void testInvalidFileName_TooLong() {
        assertFalse(myCodeInstance.validateFileName("a".repeat(51) + ".txt"), "Expected invalid filename (exceeds 50 characters).");
    }

    @Test
    void testInvalidFileName_EmptyString() {
        assertFalse(myCodeInstance.validateFileName(""), "Expected invalid filename (empty string).");
    }

    @Test
    void testInvalidFileName_SpaceInName() {
        assertFalse(myCodeInstance.validateFileName("file name.txt"), "Expected invalid filename (contains space).");
    }

    @Test
    void testHash() {
        String enteredPassword = "Pa2!Pa2!Pa2!";
        Argon2PasswordEncoder arg2Encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        String hashedPassword = arg2Encoder.encode(enteredPassword);
        assertTrue(myCodeInstance.validatePasswordMatches(enteredPassword,hashedPassword));
    }
    @Test
    void testInvalidHash() {
        String enteredPassword = "Pa2!Pa2!Pa2!";
        Argon2PasswordEncoder arg2Encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        String hashedPassword = arg2Encoder.encode(enteredPassword)+"i";
        assertFalse(myCodeInstance.validatePasswordMatches(enteredPassword,hashedPassword));
    }

    @Test
    void testDifferentPasswordsHaveDifferentHashes() {
        String password1 = "UniquePass1!";
        String password2 = "UniquePass2!";
        Argon2PasswordEncoder arg2Encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

        String hashedPassword1 = arg2Encoder.encode(password1);
        String hashedPassword2 = arg2Encoder.encode(password2);

        assertNotEquals(hashedPassword1, hashedPassword2,
                "Different passwords should produce different hashes.");
    }

    @Test
    void testIncorrectPassword() {
        String correctPassword = "SecureP@ss123";
        String wrongPassword = "WrongP@ss456";
        Argon2PasswordEncoder arg2Encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

        String hashedPassword = arg2Encoder.encode(correctPassword);

        assertFalse(myCodeInstance.validatePasswordMatches(wrongPassword, hashedPassword),
                "Expected wrong password to NOT match the correct hashed password.");
    }

    @Test
    void testShortValidPassword() {
        String enteredPassword = "A1!bcdef";
        Argon2PasswordEncoder arg2Encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        String hashedPassword = arg2Encoder.encode(enteredPassword);

        assertTrue(myCodeInstance.validatePasswordMatches(enteredPassword, hashedPassword),
                "Expected short but valid password to match its hash.");
    }

    @Test
    void testEmptyPassword() {
        String enteredPassword = "";
        Argon2PasswordEncoder arg2Encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        String hashedPassword = arg2Encoder.encode("SomeRealPassword");

        assertFalse(myCodeInstance.validatePasswordMatches(enteredPassword, hashedPassword),
                "Expected empty password to NOT match any hashed password.");
    }

    @Test
    void testLongComplexPassword() {
        String enteredPassword = "ThisIs@VeryL0ng&ComplexPassWord12345!";
        Argon2PasswordEncoder arg2Encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        String hashedPassword = arg2Encoder.encode(enteredPassword);

        assertTrue(myCodeInstance.validatePasswordMatches(enteredPassword, hashedPassword),
                "Expected long complex password to match its hash.");
    }

}