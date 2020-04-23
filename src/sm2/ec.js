const { BigInteger, SecureRandom } = require('jsbn');

/**
 * thanks for Tom Wu : http://www-cs-students.stanford.edu/~tjw/jsbn/
 *
 * Basic Javascript Elliptic Curve implementation
 * Ported loosely from BouncyCastle's Java EC code
 * Only Fp curves implemented for now
 */

const THREE = new BigInteger('3');
const ONE = new BigInteger('1');

function calculateResidue(p) {
    let bitLength = p.bitLength();
    if (bitLength > 128) {
        let firstWord = p.shiftRight(bitLength - 64);
        if (firstWord.equals(new BigInteger("-1"))) {
            return ONE.shiftLeft(bitLength).subtract(p);
        }
    }
    return null;
}
/**
 * 椭圆曲线域元素
 */
class ECFieldElementFp {
    constructor(q, x) {
        this.x = x;
        this.q = q;
        // TODO if (x.compareTo(q) >= 0) error
        this.r = calculateResidue(this.q);
    }

    /**
     * 判断相等
     */
    equals(other) {
        if (other === this) return true;
        return (this.q.equals(other.q) && this.x.equals(other.x));
    }

    /**
     * 返回具体数值
     */
    toBigInteger() {
        return this.x;
    }

    /**
     * 取反
     */
    negate() {
        return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
    }

    /**
     * 相加
     */
    add(b) {
        return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
    }

    /**
     * 相减
     */
    subtract(b) {
        return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
    }

    /**
     * 相乘
     */
    multiply(b) {
        return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
    }

    /**
     * 相除
     */
    divide(b) {
        return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
    }

    /**
     * 平方
     */
    square() {
        return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
    }
    /**
     * 开平方
     */
    sqrt() {
        if (!this.q.testBit(0)) {
            throw new Error('not done yet');
        }
        // p mod 4 == 3
        if (this.q.testBit(1)) {
            let z = new ECFieldElementFp(this.q, this.x.modPow(this.q.shiftRight(2).add(ONE), this.q));
            return z.square().equals(this) ? z : null;
        }

        let qMinusOne = this.q.subtract(ONE);
        let legendreExponent = qMinusOne.shiftRight(1);
        if (!(this.x.modPowInt(legendreExponent, this.q).equals(ONE))) {
            return null;
        }

        let u = qMinusOne.shiftRight(2);
        let k = u.shiftLeft(1).add(ONE);

        let Q = this.x;
        let fourQ = this._modDouble(this._modDouble(Q));

        let U, V;
        let rand = new SecureRandom();
        do {
            let P;
            do {
                P = new BigInteger(this.q.bitLength(), rand);
            } while (P.compareTo(this.q) >= 0
                || !(P.multiply(P).subtract(fourQ).modPow(legendreExponent, this.q).equals(qMinusOne)));
            let result = this._lucasSequence(P, Q, k);
            U = result[0];
            V = result[1];

            if (this._modMult(V, V).equals(fourQ)) {
                if (V.testBit(0)) {
                    V = V.add(this.q);
                }

                V = V.shiftRight(1);

                return new ECFieldElementFp(this.q, V);
            }
        } while (U.equals(ONE) || U.equals(qMinusOne));

        return null; // hope not here.
    }

    _modDouble(x) {
        let _2x = x.shiftLeft(1);
        if (_2x.compareTo(this.q) >= 0) {
            _2x = _2x.subtract(this.q);
        }
        return _2x;
    }

    _modMult(x, y) {
        return this._modReduce(x.multiply(y));
    }

    _modReduce(x1) {
        let x = x1;
        if (this.r) {
            let qLen = this.q.bitLength();
            while (x.bitLength() > (qLen + 1)) {
                let u = x.shiftRight(qLen);
                let v = x.subtract(u.shiftLeft(qLen));
                if (!this.r.equals(ONE)) {
                    u = u.multiply(this.r);
                }
                x = u.add(v);
            }
            while (x.compareTo(this.q) >= 0) {
                x = x.subtract(this.q);
            }
        } else {
            x = x.mod(this.q);
        }
        return x;
    }

    _lucasSequence(P, Q, k) {
        // js暂时实现不了, 随缘吧
        return [ONE, ONE]
    }
}

class ECPointFp {
    constructor(curve, x, y, z) {
        this.curve = curve;
        this.x = x;
        this.y = y;
        // 标准射影坐标系：zinv == null 或 z * zinv == 1
        this.z = z === undefined ? BigInteger.ONE : z;
        this.zinv = null;
        //TODO: compression flag
    }

    getX() {
        if (this.zinv === null) this.zinv = this.z.modInverse(this.curve.q);

        return this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q));
    }

    getY() {
        if (this.zinv === null) this.zinv = this.z.modInverse(this.curve.q);

        return this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q));
    }

    /**
     * 判断相等
     */
    equals(other) {
        if (other === this) return true;
        if (this.isInfinity()) return other.isInfinity();
        if (other.isInfinity()) return this.isInfinity();

        // u = y2 * z1 - y1 * z2
        let u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
        if (!u.equals(BigInteger.ZERO)) return false;

        // v = x2 * z1 - x1 * z2
        let v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
        return v.equals(BigInteger.ZERO);
    }

    /**
     * 是否是无穷远点
     */
    isInfinity() {
        if ((this.x === null) && (this.y === null)) return true;
        return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO);
    }

    /**
     * 取反，x 轴对称点
     */
    negate() {
        return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
    }

    /**
     * 相加
     *
     * 标准射影坐标系：
     *
     * λ1 = x1 * z2
     * λ2 = x2 * z1
     * λ3 = λ1 − λ2
     * λ4 = y1 * z2
     * λ5 = y2 * z1
     * λ6 = λ4 − λ5
     * λ7 = λ1 + λ2
     * λ8 = z1 * z2
     * λ9 = λ3^2
     * λ10 = λ3 * λ9
     * λ11 = λ8 * λ6^2 − λ7 * λ9
     * x3 = λ3 * λ11
     * y3 = λ6 * (λ9 * λ1 − λ11) − λ4 * λ10
     * z3 = λ10 * λ8
     */
    add(b) {
        if (this.isInfinity()) return b;
        if (b.isInfinity()) return this;

        let x1 = this.x.toBigInteger();
        let y1 = this.y.toBigInteger();
        let z1 = this.z;
        let x2 = b.x.toBigInteger();
        let y2 = b.y.toBigInteger();
        let z2 = b.z;
        let q = this.curve.q;

        let w1 = x1.multiply(z2).mod(q);
        let w2 = x2.multiply(z1).mod(q);
        let w3 = w1.subtract(w2);
        let w4 = y1.multiply(z2).mod(q);
        let w5 = y2.multiply(z1).mod(q);
        let w6 = w4.subtract(w5);

        if (BigInteger.ZERO.equals(w3)) {
            if (BigInteger.ZERO.equals(w6)) {
                return this.twice(); // this == b，计算自加
            }
            return this.curve.infinity; // this == -b，则返回无穷远点
        }

        let w7 = w1.add(w2);
        let w8 = z1.multiply(z2).mod(q);
        let w9 = w3.square().mod(q);
        let w10 = w3.multiply(w9).mod(q);
        let w11 = w8.multiply(w6.square()).subtract(w7.multiply(w9)).mod(q);

        let x3 = w3.multiply(w11).mod(q);
        let y3 = w6.multiply(w9.multiply(w1).subtract(w11)).subtract(w4.multiply(w10)).mod(q);
        let z3 = w10.multiply(w8).mod(q);

        return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
    }

    /**
     * 自加
     *
     * 标准射影坐标系：
     *
     * λ1 = 3 * x1^2 + a * z1^2
     * λ2 = 2 * y1 * z1
     * λ3 = y1^2
     * λ4 = λ3 * x1 * z1
     * λ5 = λ2^2
     * λ6 = λ1^2 − 8 * λ4
     * x3 = λ2 * λ6
     * y3 = λ1 * (4 * λ4 − λ6) − 2 * λ5 * λ3
     * z3 = λ2 * λ5
     */
    twice() {
        if (this.isInfinity()) return this;
        if (!this.y.toBigInteger().signum()) return this.curve.infinity;

        let x1 = this.x.toBigInteger();
        let y1 = this.y.toBigInteger();
        let z1 = this.z;
        let q = this.curve.q;
        let a = this.curve.a.toBigInteger();

        let w1 = x1.square().multiply(THREE).add(a.multiply(z1.square())).mod(q);
        let w2 = y1.shiftLeft(1).multiply(z1).mod(q);
        let w3 = y1.square().mod(q);
        let w4 = w3.multiply(x1).multiply(z1).mod(q);
        let w5 = w2.square().mod(q);
        let w6 = w1.square().subtract(w4.shiftLeft(3)).mod(q);

        let x3 = w2.multiply(w6).mod(q);
        let y3 = w1.multiply(w4.shiftLeft(2).subtract(w6)).subtract(w5.shiftLeft(1).multiply(w3)).mod(q);
        let z3 = w2.multiply(w5).mod(q);

        return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
    }

    /**
     * 倍点计算
     */
    multiply(k) {
        if (this.isInfinity()) return this;
        if (!k.signum()) return this.curve.infinity;

        // 使用加减法
        let k3 = k.multiply(THREE);
        let neg = this.negate();
        let Q = this;

        for (let i = k3.bitLength() - 2; i > 0; i--) {
            Q = Q.twice();

            let k3Bit = k3.testBit(i);
            let kBit = k.testBit(i);

            if (k3Bit !== kBit) {
                Q = Q.add(k3Bit ? this : neg);
            }
        }

        return Q;
    }
}

/**
 * 椭圆曲线 y^2 = x^3 + ax + b
 */
class ECCurveFp {
    constructor(q, a, b) {
        this.q = q;
        this.a = this.fromBigInteger(a);
        this.b = this.fromBigInteger(b);
        this.infinity = new ECPointFp(this, null, null); // 无穷远点
    }

    /**
     * 判断两个椭圆曲线是否相等
     */
    equals(other) {
        if (other === this) return true;
        return(this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b));
    }

    /**
     * 生成椭圆曲线域元素
     */
    fromBigInteger(x) {
        return new ECFieldElementFp(this.q, x);
    }

    /**
     *
     * @param {*} s
     */
    getYFromX(yTilde, xs) {
        let xbi = new BigInteger(xs, 16);
        let x = this.fromBigInteger(xbi);
        let alpha = x.square().add(this.a).multiply(x).add(this.b);
        let beta = alpha.sqrt();

        if (!beta) { throw new Error('invalid compressed X'); }

        if (beta.toBigInteger().testBit(0) != (yTilde === 1)) {
            beta = beta.negate();
        }

        return beta;
    }
    /**
     * 解析 16 进制串为椭圆曲线点
     */
    decodePointHex(s) {
        let prefix = parseInt(s.substr(0, 2), 16);
        switch (prefix) {
            // 第一个字节
            case 0:
                return this.infinity;
            case 2: // compressed
            case 3: {
                let yTilde = prefix & 1;
                let xHex = s.substr(2);
                let x = this.fromBigInteger(new BigInteger(xHex, 16));
                let y = this.getYFromX(yTilde, xHex);
                return new ECPointFp(this, x, y);
            }
            case 4: // uncompressed
            case 6: // hybrid
            case 7: { // hybrid
                let len = (s.length - 2) / 2;
                let xHex = s.substr(2, len);
                let yHex = s.substr(len + 2, len);

                return new ECPointFp(this, this.fromBigInteger(new BigInteger(xHex, 16)), this.fromBigInteger(new BigInteger(yHex, 16)));
            }
            default:
                // 不支持
                return null;
        }
    }
}

module.exports = {
    ECPointFp,
    ECCurveFp,
};
