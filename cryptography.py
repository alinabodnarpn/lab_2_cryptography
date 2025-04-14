import socket
import threading
import random
import hashlib

class RSA:
    """
    Implememtation of the RSA encryption system
    """
    @staticmethod
    def is_prime(number):
        """
        Checks if n is prime using Miller-Rabin primality test
        """
        if number <= 1:
            return False
        if number <= 3:
            return True
        if number % 2 == 0 or number % 3 == 0:
            return False
        i = 5
        w = 2
        while i * i <= number:
            if number % i == 0:
                return False
            i += w
            w = 6 - w
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
        p1 = RSA.generate_prime(bits // 2)
        p2 = RSA.generate_prime(bits // 2)
        while p1 == p2:
            p2 = RSA.generate_prime(bits // 2)

        modulus = p1 * p2
        phi = (p1 - 1) * (p2 - 1)

        e = 65537
        while RSA.gcd(e, phi) != 1:
            e = random.randint(2, phi - 1)
        private_exponent = RSA.modinv(e, phi)

        public_key = (e, modulus)
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
