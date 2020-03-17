var util = require('./util.js');

var diff1 = global.diff1 = 0x00000000ff000000000000000000000000000000000000000000000000000000;

var algos = module.exports = global.algos = {
    'kawpow': {
        multiplier: 1,
        diff: parseInt('0x00000000ff000000000000000000000000000000000000000000000000000000'),
        hash: function(){
            return function(){
                return;
            }
        }
    }
};

for (var algo in algos){
    if (!algos[algo].multiplier)
        algos[algo].multiplier = 1;
}
