import unittest
import re
from argon2 import PasswordHasher, exceptions


from DefendMyCode import (  # Assuming your Python implementation is in `DefendMyCode.py`
    add_multiply_two_integers,
    check_and_write_password,
    verify_name,
    validate_integer,
    validate_file_name,
    validate_password_matches
)
ph = PasswordHasher()  # Argon2 Password Hasher instance

class TestDefendMyCode(unittest.TestCase):

    # ✅ **Test Add & Multiply Function**
    def test_add_multiply_with_zero(self):
        self.assertEqual(add_multiply_two_integers(0, 0), [0, 0])

    def test_add_multiply_edge1(self):
        self.assertEqual(add_multiply_two_integers(-2147483648, -2147483648), [-4294967296, 4611686018427387904])

    def test_add_multiply_edge2(self):
        self.assertEqual(add_multiply_two_integers(2147483647, 2147483647), [4294967294, 4611686014132420609])

    def test_add_multiply_edge3(self):
        self.assertEqual(add_multiply_two_integers(-2147483648, 2147483647), [-1, -4611686016279904256])

    # ✅ **Test Valid Passwords**
    def test_valid_password_basic(self):
        self.assertTrue(check_and_write_password("A1b!cDxyz1"))

    def test_valid_password_with_different_punctuation(self):
        self.assertTrue(check_and_write_password("AbC1:xyz!3"))

    def test_valid_password_with_square_brackets(self):
        self.assertTrue(check_and_write_password("X1yz[]X!abc"))

    def test_valid_password_with_curly_braces(self):
        self.assertTrue(check_and_write_password("A9{bD]!xyz"))

    def test_valid_password_with_parentheses(self):
        self.assertTrue(check_and_write_password("A!1(bCxyz4)"))

    def test_valid_password_at_minimum_length(self):
        self.assertTrue(check_and_write_password("X!1yzAabc-e"))

    def test_valid_password_with_max_three_consecutive_lowercase(self):
        self.assertTrue(check_and_write_password("A1abc!Xyz7"))

    def test_valid_password_with_hyphen(self):
        self.assertTrue(check_and_write_password("A1-bCxyz!7"))

    # ❌ **Test Invalid Passwords**
    def test_invalid_password_too_short(self):
        self.assertFalse(check_and_write_password("A1b!cD"))

    def test_invalid_password_missing_uppercase(self):
        self.assertFalse(check_and_write_password("a1b!cdxyz1"))

    def test_invalid_password_missing_lowercase(self):
        self.assertFalse(check_and_write_password("A1B!CDXYZ7"))

    def test_invalid_password_missing_digit(self):
        self.assertFalse(check_and_write_password("A!bcdXYZpq"))

    def test_invalid_password_missing_punctuation(self):
        self.assertFalse(check_and_write_password("A1bcdXYZpq"))

    def test_invalid_password_too_many_consecutive_lowercase(self):
        self.assertFalse(check_and_write_password("A1bcde!XYZ7"))

    def test_invalid_password_with_disallowed_special_character(self):
        self.assertFalse(check_and_write_password("A1bcd@XYZ7"))

    def test_invalid_password_with_only_digits_and_special_characters(self):
        self.assertFalse(check_and_write_password("123!@#$%^&*()"))

    def test_invalid_password_empty(self):
        self.assertFalse(check_and_write_password(""))

    # ✅ **Test Valid Names**
    def test_valid_first_name(self):
        self.assertTrue(verify_name("Matthew"))

    def test_valid_last_name(self):
        self.assertTrue(verify_name("Uzunoe"))

    # ❌ **Test Invalid Names**
    def test_invalid_name_special_char(self):
        self.assertFalse(verify_name("J@hn"))

    def test_invalid_name_lowercase_last_name(self):
        self.assertFalse(verify_name("smith"))

    def test_invalid_name_lowercase_first_name(self):
        self.assertFalse(verify_name("matthew"))

    def test_invalid_name_space(self):
        self.assertFalse(verify_name("Smith "))

    def test_invalid_name_space_before(self):
        self.assertFalse(verify_name(" Smith"))

    def test_invalid_name_with_digit(self):
        self.assertFalse(verify_name("Sm1th"))

    def test_invalid_name_multiple_capital(self):
        self.assertFalse(verify_name("JoHNNY"))

    def test_invalid_name_empty(self):
        self.assertFalse(verify_name(""))

    def test_invalid_name_hyphen(self):
        self.assertFalse(verify_name("Uzunoe-Chin"))

    # ✅ **Test Valid Integers**
    def test_valid_int_negative(self):
        self.assertTrue(validate_integer("-1"))

    def test_valid_int_zero(self):
        self.assertTrue(validate_integer("0"))

    def test_valid_int_positive(self):
        self.assertTrue(validate_integer("100"))

    # ❌ **Test Invalid Integers**
    def test_empty_string(self):
        self.assertFalse(validate_integer(""))

    def test_only_negative_sign(self):
        self.assertFalse(validate_integer("-"))

    def test_leading_zero_positive(self):
        self.assertFalse(validate_integer("0123"))

    def test_leading_zero_negative(self):
        self.assertFalse(validate_integer("-0123"))

    def test_non_numeric_characters(self):
        self.assertFalse(validate_integer("123abc"))

    def test_special_characters(self):
        self.assertFalse(validate_integer("$100"))

    def test_too_large_number(self):
        self.assertFalse(validate_integer("10000000000"))

    def test_whitespace_input(self):
        self.assertFalse(validate_integer(" 123 "))

    # ✅ **Test Valid File Names**
    def test_valid_file_name_simple(self):
        self.assertTrue(validate_file_name("file.txt"))

    def test_valid_file_name_with_numbers(self):
        self.assertTrue(validate_file_name("file123.txt"))

    def test_valid_file_name_max_length(self):
        self.assertTrue(validate_file_name("a" * 46 + ".txt"))

    def test_valid_file_name_only_numbers(self):
        self.assertTrue(validate_file_name("1234567890.txt"))

    def test_valid_file_name_mixed_case(self):
        self.assertTrue(validate_file_name("FileName123.txt"))

    # ❌ **Test Invalid File Names**
    def test_invalid_file_name_missing_extension(self):
        self.assertFalse(validate_file_name("file"))

    def test_invalid_file_name_special_characters(self):
        self.assertFalse(validate_file_name("file@name.txt"))

    def test_invalid_file_name_too_long(self):
        self.assertFalse(validate_file_name("a" * 51 + ".txt"))

    def test_invalid_file_name_empty_string(self):
        self.assertFalse(validate_file_name(""))

    def test_invalid_file_name_space_in_name(self):
        self.assertFalse(validate_file_name("file name.txt"))

    # ✅ **Test Password Hashing**
    def test_hash(self):
        entered_password = "Pa2!Pa2!Pa2!"
        hashed_password = ph.hash(entered_password)
        self.assertTrue(validate_password_matches(entered_password, hashed_password))

    def test_invalid_hash(self):
        entered_password = "Pa2!Pa2!Pa2!"
        hashed_password = ph.hash(entered_password) + "i"
        self.assertFalse(validate_password_matches(entered_password, hashed_password))

    def test_different_passwords_have_different_hashes(self):
        password1 = "UniquePass1!"
        password2 = "UniquePass2!"
        hashed_password1 = ph.hash(password1)
        hashed_password2 = ph.hash(password2)

        self.assertNotEqual(hashed_password1, hashed_password2)

    def test_incorrect_password(self):
        correct_password = "SecureP@ss123"
        wrong_password = "WrongP@ss456"
        hashed_password = ph.hash(correct_password)

        self.assertFalse(validate_password_matches(wrong_password, hashed_password))

    def test_empty_password(self):
        entered_password = ""
        hashed_password = ph.hash("SomeRealPassword")

        self.assertFalse(validate_password_matches(entered_password, hashed_password))

    def test_long_complex_password(self):
        entered_password = "ThisIs@VeryL0ng&ComplexPassWord12345!"
        hashed_password = ph.hash(entered_password)

        self.assertTrue(validate_password_matches(entered_password, hashed_password))


if __name__ == "__main__":
    unittest.main()
