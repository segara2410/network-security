# TUGAS KELOMPOK KIJ B 2021

### Anggota Kelompok:
Kresna Adhi Pramana - 05111840000072

Ardy Wahyu Setyawan - 05111840000050

Excel Deo Cornelius - 05111840000117

Muhammad Rafi Yudhistira - 05111840000115

Segara Bhagas Dagsapurwa - 05111840000037

## Tugas 1

- implementasi 3DES dengan 2 keys dan 3 keys..

    def 3DES_2key_encrypt(k1, k2, plaintext)

    def 3DES_2key_decrypt(k1, k2, plaintext)

    def 3DES_3key_encrypt(k1, k2, k3, plaintext)
    
    def 3DES_3key_decrypt(k1, k2, k3, plaintext)

- implementasi Cipher Block Chaining Mode

    def cbc_encrypt(k, iv, plaintext)
    
    def cbc_decrypt(k, iv, plaintext)

- implementasi Counter Mode

    def ctr_encrypt(k, iv, plaintext)
    
    def ctr_decrypt(k, iv, plaintext)

    
## Tugas 2

1. implementasi MAC Based Block Cipher (DAA), lihat gambar 12.7. Gunakan asumsi yang diperlukan, agar tugas ini bisa dikerjakan.
Jelaskan mengapa anda memerlukan asumsi tsb. 
(seperti ukuran dari hashnya?)

	def MAC(K, MSG) -> h ?

2. gunakan fungsi MAC yang digunakan di nomor 1, untuk implementasi:

    - internal error control (gambar 12.2.a)

	    def enkrip_message(K, M) -> C
	    
        def dekrip_message(K, C) -> (M, valid?)

    - external error control (gambar 12.2.b)

	    def enkrip_message(K, M) -> C

	    def dekrip_message(K, C) -> (M, valid?)
