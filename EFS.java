import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * @author Dane Ukken
 * @netid: dsu220000
 * @email: dsu220000@utdallas.edu
 */
public class EFS extends Utility{
    public static int BLOCK_SIZE = 1024;
    public static int SALT_LENGTH = 16;
    public static int NONCE_LENGTH = 8;
    public static int IV_LENGTH = 16;
    public static int DOCUMENT_LENGTH = 16;
    public static int KEY_LENGTH = 16;
    public static int SECRET_DATA_LENGTH = 64;
    public static int META_HMAC_LENGTH = 64;
    public static int DATA_HMAC_LENGTH = 64;
    public static int HMAC_BLOCK_LENGTH = 128;
    public static int HMAC_KEY_BLOCK_LENGTH = 128;
    public static int USER_NAME_LENGTH = 128;
    public static int HASHED_PASSWORD_LENGTH = 32;
    public static int HEADER_LENGTH = USER_NAME_LENGTH + SALT_LENGTH + NONCE_LENGTH;

    public EFS(Editor e)
    {
        super(e);
        set_username_password();
    }

   
    /**
     * Steps to consider... <p>
     *  - add padded username and password salt to header <p>
     *  - add password hash and file length to secret data <p>
     *  - AES encrypt padded secret data <p>
     *  - add header and encrypted secret data to metadata <p>
     *  - compute HMAC for integrity check of metadata <p>
     *  - add metadata and HMAC to metadata file block <p>
     */
    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
        dir = new File(file_name);

        dir.mkdirs();
        File meta = new File(dir, "0");

        //header data
        byte[] paddedUsername = getPaddedUsername(user_name); // 128 bytes
        byte[] headerData = getNewHeaderData(paddedUsername); // 152 bytes
        //secret data
        byte[] secretData = getNewSecretData(headerData, password, 0); // 64 bytes
        byte[] hashedPassword = getHashedPasswordFromSecretData(secretData);
        byte[] key = getCryptoKey(hashedPassword);
        byte[] encryptedSecretData = Utility.encript_AES(secretData, key);
        //HMAC
        byte[] metaData = concatenateByteArrays(headerData, encryptedSecretData); // 216 bytes
        byte[] metaHMAC = computeHMAC(key, metaData); // 64 bytes
        byte[] dataHMAC = computeHMAC(key, new byte[0]); // 64 bytes
        byte[] blockHMAC = concatenateByteArrays(metaHMAC, dataHMAC); // 128 bytes

        byte[] blockData = concatenateByteArrays(metaData, blockHMAC); // 344 bytes
        byte[] paddedBlockData = getPaddedBlock(blockData);
        save_to_file(paddedBlockData, meta);
    }

    /**
     * Steps to consider... <p>
     *  - check if metadata file size is valid <p>
     *  - get username from metadata <p>
     */
    @Override
    public String findUser(String file_name) throws Exception {
        File file = new File(file_name);
        File meta = new File(file, "0");

        byte[] fileData = read_from_file(meta);
        byte[] headerData = getHeaderData(fileData);
        String obtainedUserName = (Utility.byteArray2String(getUsername(headerData))).trim();
        return obtainedUserName;
    }

    /**
     * Steps to consider...:<p>
     *  - get password, salt then AES key <p>     
     *  - decrypt password hash out of encrypted secret data <p>
     *  - check the equality of the two password hash values <p>
     *  - decrypt file length out of encrypted secret data
     */
    @Override
    public int length(String file_name, String password) throws Exception {
              File file = new File(file_name);
        File meta = new File(file, "0");

        byte[] fileData = read_from_file(meta);
        byte[] metaData = getMetadata(fileData);
        boolean canAccess = isAuthorizedUser(metaData, password);
        if(!canAccess)
        {
            throw new PasswordIncorrectException();
        }
        byte[] headerData = getHeaderData(metaData);
        byte[] salt = getSalt(headerData);
        byte[] hashedPassword = getHashedPassword(password, salt);
        byte[] key = getCryptoKey(hashedPassword);
        byte[] encryptedSecretData = getEncryptedSecretData(metaData);
        byte[] decryptedSecretData = getDecryptedSecretData(encryptedSecretData, key);
        byte[] documentLengthInBytes = getDocumentLength(decryptedSecretData);
        BigInteger documentLengthBigInt = new BigInteger(documentLengthInBytes);
        return documentLengthBigInt.intValue();
    }

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - decrypt content data of requested length 
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
        File file = new File(file_name);
        File meta = new File(file, "0");

        byte[] fileData = read_from_file(meta);
        byte[] metaData = getMetadata(fileData);
        boolean canAccess = isAuthorizedUser(metaData, password);
        if(!canAccess)
        {
            throw new PasswordIncorrectException();
        }
        byte[] headerData = getHeaderData(metaData);
        byte[] salt = getSalt(headerData);
        byte[] nonce = getNonce(headerData);
        byte[] hashedPassword = getHashedPassword(password, salt);
        byte[] key = getCryptoKey(hashedPassword);
        int file_length = length(file_name, password);

        if (len < 0 || starting_position < 0 || starting_position > file_length || starting_position + len > file_length) {
            throw new Exception();
        }

        byte[] result = new byte[len];
        if (file_length == 0) {
            return result;
        }
        int blockStart = (starting_position / BLOCK_SIZE) + 1;
        int startOffset = starting_position % BLOCK_SIZE;
        int blockEnd = ((starting_position + len) / BLOCK_SIZE) + 1;
        int encryptedChunksPerBlock = BLOCK_SIZE / IV_LENGTH;
        long counter = (long) (blockStart - 1) * encryptedChunksPerBlock;

        int readBlocks = 0;
        for (int i = blockStart; i <= blockEnd; i++) {
            File block = new File(file, Integer.toString(i));
            byte[] encryptedBlockData = read_from_file(block);

            ByteBuffer counterBlockBuffer = ByteBuffer.allocate(IV_LENGTH);
            counterBlockBuffer.put(nonce);
            counterBlockBuffer.putLong(counter);
            byte[] counterBlock = counterBlockBuffer.array(); //initial vector

            byte[] decryptedBlockData = decryptCTR(encryptedBlockData, key, counterBlock);
            //byte[] decryptedBlockData = encryptedBlockData;
            int start = 0;
            int currBlockReadLength = BLOCK_SIZE;
            if (blockStart == i) {
                start = startOffset;
                currBlockReadLength = Math.min(len + starting_position, BLOCK_SIZE-startOffset);
            } else if (blockEnd == i) {
                currBlockReadLength = (starting_position + len) % BLOCK_SIZE;
            }

            System.arraycopy(decryptedBlockData, start, result, readBlocks*BLOCK_SIZE, currBlockReadLength-start);
            readBlocks += 1;
            counter += encryptedChunksPerBlock;
        }

    	return result;
    }

    
    /**
     * Steps to consider...:<p>
	 *	- verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - ### main procedure for update the encrypted content ### <p>
     *  - compute new HMAC and update metadata 
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
        File file = new File(file_name);
        File meta = new File(file, "0");
        int file_length = length(file_name, password);

        if (content.length < 0 || starting_position < 0 || starting_position > file_length) {
            throw new Exception();
        }

        byte[] existingContent = read(file_name, 0, file_length, password);
        byte[] newContent = new byte[Math.max(file_length, starting_position + content.length)];
        System.arraycopy(existingContent, 0, newContent, 0, existingContent.length);
        System.arraycopy(content, 0, newContent, starting_position, content.length);

        writeWithNewContent(newContent, file_length, file, meta);
    }

    /**
     * Steps to consider...:<p>
  	 *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
        // get stored dataHmac and metaHmac
        File file = new File(file_name);
        File metaFile = new File(file, "0");
        byte[] metaFileData = read_from_file(metaFile);
        byte[] blockHMAC = getHMACBlockFromMetaData(metaFileData);
        byte[] metaHMAC = getMetaHMACFromData(blockHMAC);
        byte[] dataHMAC = getDataHMACFromData(blockHMAC);

        int documentLength = length(file_name, password); // checks for password correctness as well

        // get computed dataHmac and metaHmac
        byte[] data = read(file_name, 0, documentLength, password);
        byte[] metaData = getMetadata(metaFileData);
        byte[] headerData = getHeaderData(metaData);
        byte[] salt = getSalt(headerData);
        byte[] hashedPassword = getHashedPassword(password, salt);
        byte[] key = getCryptoKey(hashedPassword);

        byte[] computedMetaHMAC = computeHMAC(key, metaData);
        byte[] computedDataHMAC = computeHMAC(key, data);

        boolean isMetaDataUntampered = Arrays.equals(metaHMAC, computedMetaHMAC);
        boolean isDataUntampered = Arrays.equals(dataHMAC, computedDataHMAC);

        return isDataUntampered && isMetaDataUntampered;
  }

    /**
     * Steps to consider... <p>
     *  - verify password <p>
     *  - truncate the content after the specified length <p>
     *  - re-pad, update metadata and HMAC <p>
     */
    @Override
    public void cut(String file_name, int length, String password) throws Exception {
        File file = new File(file_name);
        File meta = new File(file, "0");
        //byte[] metaData = getMetadata(read_from_file(meta));
        int file_length = length(file_name, password);

        if (length < 0 || length > file_length) {
            throw new Exception();
        }

        byte[] existingContent = read(file_name, 0, file_length, password);
        byte[] newContent = new byte[length];
        System.arraycopy(existingContent, 0, newContent, 0, length);

        writeWithNewContent(newContent, file_length, file, meta);
    }

    public static byte[] getPaddedUsername(String username) {
        StringBuilder usernameBuilder = new StringBuilder(username);
        while (usernameBuilder.length() < USER_NAME_LENGTH) {
            usernameBuilder.append('\0');
        }
        username = usernameBuilder.toString();
        byte[] paddedUsername = new byte[USER_NAME_LENGTH];
        byte[] usernameBytes = username.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(usernameBytes, 0, paddedUsername, 0, Math.min(usernameBytes.length, paddedUsername.length));
        return paddedUsername;
    }

    public static byte[] getHashedPassword(String password, byte[] salt) {
        byte[] passwordBytes = password.getBytes(StandardCharsets.US_ASCII);
        byte[] passwordAndSalt = new byte[passwordBytes.length + salt.length];
        System.arraycopy(passwordBytes, 0, passwordAndSalt, 0, passwordBytes.length);
        System.arraycopy(salt, 0, passwordAndSalt, passwordBytes.length, salt.length);
        byte[] hashedPassword;
        try {
            hashedPassword = Utility.hash_SHA256(passwordAndSalt);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return hashedPassword;
    }

    public static byte[] concatenateByteArrays(byte[]... arrays) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (byte[] array : arrays) {
            outputStream.write(array);
        }
        return outputStream.toByteArray();
    }

    public static byte[] getPaddedBlock(byte[] data) throws Exception {
        // Calculate how much padding is needed to reach BLOCK_SIZE
        int originalLength = data.length;
        int paddingLength = BLOCK_SIZE - (originalLength % BLOCK_SIZE);
        if (paddingLength == BLOCK_SIZE) {
            paddingLength = 0;
        }

        byte[] finalData = new byte[originalLength + paddingLength];
        System.arraycopy(data, 0, finalData, 0, originalLength);

        return finalData;
    }

    public static byte[] xorWithKey(byte[] a, byte[] key) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ key[i % key.length]);
        }
        return out;
    }

    public static byte[] encryptCTR(byte[] data, byte[] key, byte[] iv) throws Exception {
        if (iv.length != 16) {
            throw new IllegalArgumentException("IV must be 16 bytes long");
        }
        byte[] encryptedData = new byte[data.length];
        // Separate the nonce and counter from the IV
        byte[] nonce = Arrays.copyOfRange(iv, 0, 8);
        byte[] counterBytes = Arrays.copyOfRange(iv, 8, 16);
        long counter = ByteBuffer.wrap(counterBytes).getLong();
        byte[] encryptedCounter;

        for (int blockStart = 0; blockStart < data.length; blockStart += 16) {
            // Combine nonce and counter
            ByteBuffer counterBlockBuffer = ByteBuffer.allocate(16);
            counterBlockBuffer.put(nonce);
            counterBlockBuffer.putLong(counter);
            byte[] counterBlock = counterBlockBuffer.array();

            encryptedCounter = encript_AES(counterBlock, key);
            int blockEnd = Math.min(blockStart + 16, data.length);
            byte[] dataBlock = new byte[blockEnd - blockStart];
            System.arraycopy(data, blockStart, dataBlock, 0, dataBlock.length);

            // XOR the data block with the encrypted counter block
            byte[] encryptedBlock = xorWithKey(dataBlock, encryptedCounter);
            System.arraycopy(encryptedBlock, 0, encryptedData, blockStart, encryptedBlock.length);
            counter++;
        }

        return encryptedData;
    }

    public static byte[] decryptCTR(byte[] data, byte[] key, byte[] iv) throws Exception {
        return encryptCTR(data, key, iv);
    }

    public static byte[] trimNullBytes(byte[] bytes) {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0) {
            --i;
        }
        return Arrays.copyOf(bytes, i + 1);
    }

    public static byte[] getMetadata(byte[] fileData) {
        return Arrays.copyOfRange(fileData, 0, HEADER_LENGTH + SECRET_DATA_LENGTH);
    }

    public static byte[] getEncryptedSecretData(byte[] metaData) {
        return Arrays.copyOfRange(metaData, HEADER_LENGTH, HEADER_LENGTH + SECRET_DATA_LENGTH);
    }

    public static byte[] getHMACBlockFromMetaData(byte[] metaFileData) {
        return Arrays.copyOfRange(metaFileData, HEADER_LENGTH + SECRET_DATA_LENGTH, HEADER_LENGTH + SECRET_DATA_LENGTH + HMAC_BLOCK_LENGTH);
    }

    // metadata is not decrypted before converting to HMAC
    public static byte[] getMetaHMACFromData(byte[] blockHMAC) {
        return Arrays.copyOfRange(blockHMAC, 0, META_HMAC_LENGTH);
    }

    // data is not encrypted before converting to HMAC
    public static byte[] getDataHMACFromData(byte[] blockHMAC) {
        return Arrays.copyOfRange(blockHMAC, META_HMAC_LENGTH, META_HMAC_LENGTH + DATA_HMAC_LENGTH);
    }

    public static byte[] getHeaderData(byte[] metaData) {
        return Arrays.copyOfRange(metaData, 0, HEADER_LENGTH);
    }

    public static byte[] getSalt(byte[] headerData) {
        return Arrays.copyOfRange(headerData, USER_NAME_LENGTH, USER_NAME_LENGTH + SALT_LENGTH);
    }

    public static byte[] getUsername(byte[] headerData) {
        return Arrays.copyOfRange(headerData, 0, USER_NAME_LENGTH);
    }

    public static byte[] getDecryptedSecretData(byte[] encryptedSecretData, byte[] initialVector) throws Exception {
        return Utility.decript_AES(encryptedSecretData, initialVector);
    }

    public static byte[] getDocumentLength(byte[] decryptedSecretData) {
        return Arrays.copyOfRange(decryptedSecretData, HASHED_PASSWORD_LENGTH, HASHED_PASSWORD_LENGTH + DOCUMENT_LENGTH);
    }

    public static byte[] getPaddedDocumentLength(byte[] documentLength) {
        byte[] paddedBytes = new byte[16];
        int numberOfLeadingZeros = DOCUMENT_LENGTH - documentLength.length;
        System.arraycopy(documentLength, 0, paddedBytes, numberOfLeadingZeros, documentLength.length);
        return paddedBytes;
    }

    public static byte[] getCryptoKey(byte[] hashedPassword) {
        return Arrays.copyOfRange(hashedPassword, 0, KEY_LENGTH);
    }

    public static byte[] getHashedPasswordFromSecretData(byte[] secretData) {
        return Arrays.copyOfRange(secretData, 0, HASHED_PASSWORD_LENGTH);
    }

    public static byte[] getKeyFromSecretData(byte[] secretData) {
        return Arrays.copyOfRange(secretData, HASHED_PASSWORD_LENGTH + DOCUMENT_LENGTH, HASHED_PASSWORD_LENGTH + DOCUMENT_LENGTH + KEY_LENGTH);
    }

    public static byte[] getNonce(byte[] headerData) {
        return Arrays.copyOfRange(headerData, USER_NAME_LENGTH + SALT_LENGTH, USER_NAME_LENGTH + SALT_LENGTH + NONCE_LENGTH);
    }

    public static boolean isAuthorizedUser(byte[] metaData, String password) throws RuntimeException {
        byte[] salt = getSalt(getHeaderData(metaData));
        byte[] hashedPassword = getHashedPassword(password, salt);
        byte[] key = getCryptoKey(hashedPassword);
        byte[] encryptedSecretData = getEncryptedSecretData(metaData);
        byte[] decryptedSecretData;
        try {
            decryptedSecretData = getDecryptedSecretData(encryptedSecretData, key);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        byte[] storedHashedPassword = Arrays.copyOfRange(decryptedSecretData, 0, HASHED_PASSWORD_LENGTH);
        return Arrays.equals(hashedPassword, storedHashedPassword);
    }

    public static byte[] getNewHeaderData(byte[] paddedUserName) {
        byte[] salt = Utility.secureRandomNumber(16); // 16 bytes
        byte[] nonce = Utility.secureRandomNumber(8);
        ByteBuffer headerDataBuffer = ByteBuffer.allocate(HEADER_LENGTH);
        headerDataBuffer.put(paddedUserName);
        headerDataBuffer.put(salt);
        headerDataBuffer.put(nonce);
        byte[] headerData = headerDataBuffer.array();
        return headerData;
    }

    public static byte[] getNewSecretData(byte[] headerData, String password, int fileLength) {
        byte[] salt = getSalt(headerData);
        byte[] hashedPassword = getHashedPassword(password, salt);
        byte[] documentLength = BigInteger.valueOf(fileLength).toByteArray();
        byte[] paddedDocumentBytes = getPaddedDocumentLength(documentLength);
        byte[] key = Arrays.copyOfRange(hashedPassword, 0, KEY_LENGTH);
        ByteBuffer secretDataBuffer = ByteBuffer.allocate(SECRET_DATA_LENGTH);
        secretDataBuffer.put(hashedPassword);
        secretDataBuffer.put(paddedDocumentBytes);
        secretDataBuffer.put(key);
        byte[] secretData = secretDataBuffer.array();
        return secretData;
    }

    public void writeToFiles(int fileLength, byte[] newContent, byte[] key, byte[] nonce, File file) throws Exception {
        long counter = 0;
        int totalBlocks = fileLength / BLOCK_SIZE;
        if (fileLength % BLOCK_SIZE != 0) {
            totalBlocks += 1;
        }
        for(int i = 1; i <= totalBlocks; i++) {
            File block = new File(file, Integer.toString(i));

            ByteBuffer counterBlockBuffer = ByteBuffer.allocate(IV_LENGTH);
            counterBlockBuffer.put(nonce);
            counterBlockBuffer.putLong(counter);
            byte[] counterBlock = counterBlockBuffer.array(); //initial vector

            int start = (i - 1) * BLOCK_SIZE;
            int end = i * BLOCK_SIZE;
            if (i == totalBlocks) {
                end = fileLength;
            }
            byte[] blockData = Arrays.copyOfRange(newContent, start, end);
            if (i == totalBlocks) {
                blockData = getPaddedBlock(blockData);
            }
            byte[] encryptedBlockData = encryptCTR(blockData, key, counterBlock);
            save_to_file(encryptedBlockData, block);

            int encryptedChunksPerBlock = BLOCK_SIZE / IV_LENGTH;
            counter += encryptedChunksPerBlock;
        }
    }
    
    public void deleteDataFiles(int file_length, File file) {
        int oldBlocksCount = file_length / BLOCK_SIZE;
        if (file_length % BLOCK_SIZE != 0) {
            oldBlocksCount += 1;
        }
        //delete old blocks
        for(int i = 1; i <= oldBlocksCount; i++) {
            File block = new File(file, Integer.toString(i));
            try {
                block.delete();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public void writeWithNewContent(byte[] newContent, int file_length, File file, File meta) throws Exception {
        byte[] metaFileData = read_from_file(meta);
        byte[] metaData = getMetadata(metaFileData);
        byte[] headerData = getHeaderData(metaData);
        byte[] paddedUsername = getUsername(headerData);
        byte[] newHeaderData = getNewHeaderData(paddedUsername);

        int newFileLength = newContent.length;
        byte[] secretData = getNewSecretData(newHeaderData, password, newFileLength);
        byte[] key = getKeyFromSecretData(secretData);
        byte[] nonce = getNonce(newHeaderData);

        deleteDataFiles(file_length, file);
        writeToFiles(newFileLength, newContent, key, nonce, file);

        byte[] encryptedSecretData = Utility.encript_AES(secretData, key);
        byte[] newMetaData = concatenateByteArrays(newHeaderData, encryptedSecretData);

        byte[] metaHMAC = computeHMAC(key, newMetaData);
        byte[] dataHMAC = computeHMAC(key, newContent);
        byte[] blockHMAC = concatenateByteArrays(metaHMAC, dataHMAC);

        byte[] blockData = concatenateByteArrays(newMetaData, blockHMAC);
        byte[] paddedBlockData = getPaddedBlock(blockData);
        save_to_file(paddedBlockData, meta);
    }

    public static byte[] computeHMAC(byte[] key, byte[] message) throws Exception {
        byte[] keyPadded = Arrays.copyOf(key, HMAC_KEY_BLOCK_LENGTH);
        byte[] ipad = new byte[HMAC_KEY_BLOCK_LENGTH];
        byte[] opad = new byte[HMAC_KEY_BLOCK_LENGTH];
        Arrays.fill(ipad, (byte) 0x36);
        Arrays.fill(opad, (byte) 0x5C);

        // XOR Key with Paddings
        for (int i = 0; i < HMAC_KEY_BLOCK_LENGTH; i++) {
            ipad[i] ^= keyPadded[i]; //ipad xor with key
            opad[i] ^= keyPadded[i]; //opad xor with key
        }

        byte[] ipadAndMessage = concatenateByteArrays(ipad, message);
        byte[] innerHash = Utility.hash_SHA512(ipadAndMessage);
        byte[] opadAndInnerHash = concatenateByteArrays(opad, innerHash);
        byte[] finalHash = Utility.hash_SHA512(opadAndInnerHash);
        return finalHash;
    }
}
