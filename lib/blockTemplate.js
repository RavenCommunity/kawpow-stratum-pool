var bignum = require('bignum');
var crypto = require('crypto');
var SHA3 = require('sha3');

var merkle = require('./merkleTree.js');
var transactions = require('./transactions.js');
var util = require('./util.js');

    
/**
 * The BlockTemplate class holds a single job.
 * and provides several methods to validate and submit it to the daemon coin
**/
var BlockTemplate = module.exports = function BlockTemplate(jobId, rpcData, reward, recipients, poolAddress){

    //epoch length
    const EPOCH_LENGTH = 7500;
    
    //private members
    var submits = [];

    //public members
    this.rpcData = rpcData;
    this.jobId = jobId;

    // get target info
    this.target = bignum(rpcData.target, 16);
    this.target_hex = rpcData.target;

    this.difficulty = parseFloat((diff1 / this.target.toNumber()).toFixed(9));
    console.log("In BlockTemplate difficulty is "+this.difficulty);

    //nTime
    var nTime = util.packUInt32BE(rpcData.curtime).toString('hex');

    //current time of issuing the template
    var curTime = Date.now() / 1000 | 0;

    // generate the fees and coinbase tx
    var blockReward = this.rpcData.coinbasevalue;
 
    var fees = [];
    rpcData.transactions.forEach(function(value) {
        fees.push(value);
    });
    this.rewardFees = transactions.getFees(fees);
    rpcData.rewardFees = this.rewardFees;

    if (typeof this.genTx === 'undefined') {
        this.genTx = transactions.createGeneration(rpcData, blockReward, this.rewardFees, recipients, poolAddress).toString('hex');
        this.genTxHash = transactions.txHash();
        
        // console.log('this.genTxHash: ' + transactions.txHash());
        // console.log('this.merkleRoot: ' + merkle.getRoot(rpcData, this.genTxHash));
    }

    // generate the merkle root
    this.prevHashReversed = util.reverseBuffer(new Buffer(rpcData.previousblockhash, 'hex')).toString('hex');
    this.merkleRoot = merkle.getRoot(rpcData, this.genTxHash);
    this.txCount = this.rpcData.transactions.length + 1; // add total txs and new coinbase
    this.merkleRootReversed = util.reverseBuffer(new Buffer(this.merkleRoot, 'hex')).toString('hex');
    // we can't do anything else until we have a submission

    // console.log('this.prevHashReversed: ' + this.prevHashReversed);

    this.serializeHeader = function() {
        var header =  new Buffer(80);
        var position = 0;

        header.write(util.packUInt32BE(this.rpcData.height).toString('hex'), position, 4, 'hex'); // height 42-46
        header.write(this.rpcData.bits, position += 4, 4, 'hex'); // bits 47-50
        header.write(nTime, position += 4, 4, 'hex');                        // nTime          51-54
        header.write(this.merkleRoot, position += 4, 32, 'hex');                  // merkelRoot     55-87
        header.write(this.rpcData.previousblockhash, position += 32, 32, 'hex');  // prevblockhash  88-120
        header.writeUInt32BE(this.rpcData.version, position + 32, 4);                // version        121-153

        header = util.reverseBuffer(header);
        return header;
    };

    // join the header and txs together
    this.serializeBlock = function(header_hash, nonce, mixhash) {

        header = this.serializeHeader();
        var foo = new Buffer(40);

        foo.write(util.reverseBuffer(nonce).toString('hex'), 0, 8, 'hex');
        foo.write(util.reverseBuffer(mixhash).toString('hex'), 8, 32,'hex');

        buf = new Buffer.concat([
            header,
            foo,
            util.varIntBuffer(this.rpcData.transactions.length + 1),
            new Buffer(this.genTx, 'hex')
        ]);

        if (this.rpcData.transactions.length > 0) {
            this.rpcData.transactions.forEach(function (value) {
                tmpBuf = new Buffer.concat([buf, new Buffer(value.data, 'hex')]);
                buf = tmpBuf;
            });
        }

        /*
        console.log('header: ' + header.toString('hex'));
        console.log('soln: ' + soln.toString('hex'));
        console.log('varInt: ' + varInt.toString('hex'));
        console.log('this.genTx: ' + this.genTx);
        console.log('data: ' + value.data);
        console.log('buf_block: ' + buf.toString('hex'));
        console.log('blockhex: ' + buf.toString('hex'));
        */
        return buf;
    };

    // submit header_hash and nonce
    this.registerSubmit = function(header, nonce){
        var submission = header + nonce;
        if (submits.indexOf(submission) === -1){
            submits.push(submission);
            return true;
        }
        return false;
    };


    //powLimit * difficulty
    var powLimit = algos.kawpow.diff; // TODO: Get algos object from argument
    var adjPow = (powLimit / this.difficulty);
    if ((64 - adjPow.toString(16).length) === 0) {
        var zeroPad = '';
    }
    else {
        var zeroPad = '0';
        zeroPad = zeroPad.repeat((64 - (adjPow.toString(16).length)));
    }
    var target = (zeroPad + adjPow.toString(16)).substr(0,64);
    //this.target_share_hex = target;

    let d = new SHA3.SHA3Hash(256);
    var seedhash_buf = new Buffer(32);
    var seedhash = seedhash_buf.toString('hex');
    this.epoch_number = Math.floor(this.rpcData.height / EPOCH_LENGTH);
    for (var i=0; i<this.epoch_number; i++) {
        d = new SHA3.SHA3Hash(256);
        d.update(seedhash_buf);
        seedhash_buf = d.digest();
        seedhash = d.digest('hex');
        // console.log("seedhash(#"+i+")= "+seedhash.toString('hex'));
    }
    
    var header_hash = this.serializeHeader(); // 140 bytes (doesn't contain nonce or mixhash)
    // console.log("****************************");
    // console.log("Header hash sent to miners: "+header_hash.toString('hex'));
    // console.log("****************************");
    header_hash = util.reverseBuffer(util.sha256d(header_hash)).toString('hex');

    //change override_target to a minimum wanted target. This is useful for e.g. testing on testnet.
    var override_target = 0;
    //override_target = 0x0000000FFFFF0000000000000000000000000000000000000000000000000000;
	if ((override_target != 0) && (adjPow > override_target)) {
		zeroPad = '0';
        zeroPad = zeroPad.repeat((64 - (override_target.toString(16).length)));
        target = (zeroPad + override_target.toString(16)).substr(0,64);
    }
    
    // used for mining.notify
    this.getJobParams = function(){
        // console.log("RPC DATA IN job params: "+JSON.stringify(this.rpcData));
        if (!this.jobParams){
            this.jobParams = [
                this.jobId,
                header_hash,
                seedhash,
                target,  //target is overridden later to match miner varDiff
                true,
                this.rpcData.height,
                this.rpcData.bits
            ];
        }
        return this.jobParams;
    };
};

