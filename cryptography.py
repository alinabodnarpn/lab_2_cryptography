import socket
import threading
import random
import hashlib

class RSA:
    """
    Implememtation of the RSA encryption system
    """
    @staticmethod
    def is_prime(number, rounds=5):
        """
        Checks if n is prime using Miller-Rabin primality test
        """
        if number <= 1:
            return False
        if number <= 3:
            return True
        if number % 2 == 0:
            return False
        odd_part = number - 1
        power_of_two = 0
        while odd_part % 2 == 0:
            odd_part //= 2
            power_of_two += 1
        for _ in range(rounds):
            base = random.randint(2, number - 2)
            result = pow(base, odd_part, number)

            if result in (1, number - 1):
                continue

            for _ in range(power_of_two - 1):
                result = pow(result, 2, number)
                if result == number - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def generate_prime(bits):
        """
        Generates a prime number of specified bit length
        """
        while True:
            p = random.getrandbits(bits)
            p = p | (1 << (bits - 1))
            if RSA.is_prime(p):
                return p

    @staticmethod
    def gcd(a, b):
        """
        Computes the greatest common divisor of a and b
        """
        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def extended_gcd(a, b):
        """
        Extended Euclidean Algorithm to find integers x, y so that ax + by = gcd(a, b)
        """
        if a == 0:
            return (b, 0, 1)
        gcd, x1, y1 = RSA.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return (gcd, x, y)

    @staticmethod
    def modinv(a, m):
        """
        Compute the modular inverse of a modulo m
        """
        gcd, x, _ = RSA.extended_gcd(a, m)
        if gcd != 1:
            return None
        return x % m

    @staticmethod
    def generate_keys(bits=128):
        """
        Generate RSA public and private keys.
        """
        prime1 = RSA.generate_prime(bits // 2)
        prime2 = RSA.generate_prime(bits // 2)
        while prime1 == prime2:
            prime2 = RSA.generate_prime(bits // 2)

        modulus = prime1 * prime2
        phi = (prime1 - 1) * (prime2 - 1)

        public_exponent = 65537
        while RSA.gcd(public_exponent, phi) != 1:
            public_exponent = random.randint(2, phi - 1)
        private_exponent = RSA.modinv(public_exponent, phi)

        public_key = (public_exponent, modulus)
        private_key = (private_exponent, modulus)

        return public_key, private_key

    @staticmethod
    def encrypt(message, public_key):
        """
        Encrypts a string message using the RSA public key
        """
        e, n = public_key
        encrypted = [pow(ord(char), e, n) for char in message]
        return encrypted

    @staticmethod
    def decrypt(encrypted, private_key):
        """
        Decrypts a list of integers back into the original message using the RSA private key
        """
        d, n = private_key
        decrypted = [chr(pow(char, d, n)) for char in encrypted]
        return ''.join(decrypted)
