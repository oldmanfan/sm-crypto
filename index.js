const BIP39 = require("bip39");
const sm2 = require('./src/sm2/index');
const mnemonic = {
  /**
   * 生成一对密钥及对应的助记词.
   * @param { boolean } compressed 是否压缩公钥
   * @returns {{mnemonic: *, publicKey: (*|string), privateKey: *}}
   */
  generateKeyPairAndMnemonic: (compressed = true) => {
    const mnemonic = BIP39.generateMnemonic();
    const seed = BIP39.mnemonicToSeed(mnemonic).toString("hex");
    const keypair = sm2.generateKeyPairHexBySeed(seed, compressed);
    return {
      mnemonic: mnemonic,
      publicKey: keypair.publicKey,
      privateKey: keypair.privateKey,
    };
  },

  /**
   * 通过助记词生成一对密钥.
   * @param { String } mnemonic 助记词
   * @param { boolean } compressed 是否压缩公钥
   * @returns {{publicKey: (*|string), privateKey: *}}
   */
  generateKeyPairByMnemonic: (mnemonic, compressed = true) => {
    const seed = BIP39.mnemonicToSeed(mnemonic).toString("hex");
    const keypair = sm2.generateKeyPairHexBySeed(seed, compressed);
    return {
      publicKey: keypair.publicKey,
      privateKey: keypair.privateKey,
    };
  }
}

module.exports = {
    mnemonic,
    sm2,
    sm3: require('./src/sm3/index'),
    sm4: require('./src/sm4/index'),
};
