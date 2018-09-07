pragma solidity ^0.4.16;


contract AbstractENS {
    function owner(bytes32) constant returns(address);
    function resolver(bytes32) constant returns(address);
    function setOwner(bytes32, address);
    function setSubnodeOwner(bytes32, bytes32 label, address);
    function setResolver(bytes32, address);
}

contract Resolver {
    function setAddr(bytes32, address);
}

contract ReverseRegistrar {
    function claim(address) returns (bytes32);
}


contract Wallet {

    // namehash('addr.reverse')
    bytes32 constant RR_NODE = 0x91d1777781884d03a6757a803996e38de2a42967fb37eeaca72729271025a9e2;


    event passwordResetStarted();
    event masterChanged(address oldMaster, address newMaster);


    // @TODO: Enforce password policies
    //uint64 constant maxPasswordAge = 12 weeks;
    //uint64 constant minResetRequestPeriod = 3 hours;
    // Cannot use wallet after this date; must change/reset password
    //uint64 _nextPasswordChange;

    // Cannot request (another) password reset until after this date
    //uint64 _nextPasswordReset;

    uint256 _nonce;

    // Account that controls this wallet with signed messages
    address _master;

    // The extra salt used during key derivation for the master account
    bytes32 _extraSalt;
    uint32 _encryptedScryptParameters;

    // The remaining amount the lendee has to pay
    uint256 _debtReserved;

    // The remaining amount for the lender to withdrawl
    uint256 _debtRemaining;

    Registrar _registrar;


    function Wallet(address registrar, uint256  debt, address master, bytes32 extraSalt, uint32 encryptedScryptParameters) {
        _registrar = Registrar(registrar);

        _debtRemaining = debt;

        _master = master;
        _extraSalt = extraSalt;
        _encryptedScryptParameters = encryptedScryptParameters;
        //ReverseRegistrar(_ens.owner(RR_NODE)).claim(_registrar);


        // @todo: setup reverse records...
    }

    // @TODO: Allow tokens

    /*
    // @TODO: allow general operations (once paid off)
    function exec(...) returns (bool success) {
        if (_debtRemaining > 0) { return false; }
        ...
    }
    */

    function send(address to, uint256 amount, uint256 nonce) returns (bool success) {
        if (amount + _debtReserved > this.balance || amount + _debtReserved < amount) { return false; }

        if (msg.sender != _master) { return false; }

        if (to.send(amount)) {
            _nonce++;
            return true;
        }

        return false;
    }

    function sendSignedTransaction(address to, uint256 amount, uint256 nonce, uint8 sigV, bytes32 sigR, bytes32 sigS) returns (bool success) {
        if (amount + _debtReserved > this.balance || amount + _debtReserved < amount) { return false; }

        if (nonce != _nonce) { return false; }

        bytes32 digest = keccak256(to, amount, nonce);
        address master = ecrecover(digest, sigV, sigR, sigS);
        if (msg.sender != _master) { return false; }

        if (to.send(amount)) {
            _nonce++;
            return true;
        }

        return false;
    }

    /*
    function beginPasswordReset(bytes32 token, uint8 sigV, bytes32 sigR, bytes32 sigS) {
        require(now > _lastPasswordResetRequest);
    }

    function cancelResetPassword(..., uint8 sigV, bytes32 sigR, bytes32 sigS) {
        address maybeMaster = ecrecover(..., sigV, sigR, sigS);
    }

    function finalizePasswordReset() {
    }
    */

    function changeMaster(address newMaster, bytes32 newExtraSalt, uint256 nonce, uint8 sigV, bytes32 sigR, bytes32 sigS) returns (bool success) {
        if (_nonce != nonce) { return false; }

        bytes32 digest = keccak256(newMaster, newExtraSalt, nonce);
        address oldMaster = ecrecover(digest, sigV, sigR, sigS);

        if (oldMaster != _master) { return false; }
        masterChanged(_master, newMaster);

        _extraSalt = newExtraSalt;
        _master = newMaster;

        _nonce++;
    }

    function walletInfo() constant returns (uint256 nonce, address master, bytes32 extraSalt, uint32 encryptedScryptParameters) {
        return (_nonce, _master, _extraSalt, encryptedScryptParameters);
    }

    // Usually called by the lender, to claim their money. In the worst case, can be
    // called by the master (which would require adding gas money to the EOA)
    function withdrawlPayment(uint256 amount) {
        require(msg.sender == address(_registrar) || msg.sender == _master);
        require(amount <= _debtReserved);
        _debtReserved -= amount;
        _debtRemaining -= amount;
        assert(_registrar.send(amount));
    }

    // Pay the contract and depending on the current debt, put some away for the lender
    function () payable {
        if (_debtRemaining > _debtReserved) {
            uint256 maxInstallment = _debtRemaining - _debtReserved;

            uint256 installment = msg.value / 4;
            if (installment > maxInstallment) {
                installment = maxInstallment;
            }

            _debtReserved += installment;
        }
    }
}

contract Registrar {

    // namehash('addr.reverse')
    bytes32 constant RR_NODE = 0x91d1777781884d03a6757a803996e38de2a42967fb37eeaca72729271025a9e2;

    event ownerChanged(address oldOwner, address newOwner);

    AbstractENS _ens;
    address _owner;

    Resolver _defaultResolver;

    bytes32 _nodehash;

    function Registrar(address ens, address defaultResolver, bytes32 nodehash, string name) {
        _ens = AbstractENS(ens);
        _defaultResolver = Resolver(defaultResolver);
        _nodehash = nodehash;

        _owner = msg.sender;

        // Give the owner access to the reverse entry
        //ReverseRegistrar(_ens.owner(RR_NODE)).claim(_owner);
    }

    function withdrawl(uint256 amount) {
        require(msg.sender == _owner);
        assert(_owner.send(amount));
    }

    function setOwner(address newOwner) {
        require(msg.sender == _owner);
        _owner = newOwner;

        // Give the owner access to the reverse entry
        //ReverseRegistrar(_ens.owner(RR_NODE)).claim(_owner);
    }

    function register(bytes32 labelHash, address master, bytes32 extraSalt, uint32 encryptedScryptParameters) {
        require(msg.sender == _owner);

        //! "HEllo"
        //! master

        Wallet wallet = new Wallet(this, 0.1 ether, master, extraSalt, encryptedScryptParameters);

        var nodehash = sha3(_nodehash, labelHash);

        // Already owned
        require(_ens.owner(nodehash) == address(0));

        // Make this registrar the owner (so we can set it up before giving it away)
        _ens.setSubnodeOwner(_nodehash, labelHash, this);

        // Set up the default resolver and point to the sender
        _ens.setResolver(nodehash, _defaultResolver);
        _defaultResolver.setAddr(nodehash, wallet);

        // Now give it to the sender
        _ens.setOwner(nodehash, msg.sender);
    }

    function () payable {
    }
}

