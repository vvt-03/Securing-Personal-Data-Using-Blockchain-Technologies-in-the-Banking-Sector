// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CustomerManagement {
    
    struct Customer {
        string geography;
        uint256 creditScore;
        uint256 age;
        uint256 balance;
        bool hasCrCard;
        uint256 estimatedSalary;
        bytes32 passwordHash; // Store hashed passwords
    }

    
    address public owner; // Contract Owner
    mapping(address => bool) public managers; // List of managers
    mapping(uint256 => Customer) public customers; // List of customers
    mapping(address => uint256) public managerOTPs; // OTPs for managers
    mapping(uint256 => uint256) public customerOTPs; // OTPs for customers
    string private managerPasswordHash; // Hashed Manager Password
    uint256 public customerCount;

    
    event OTPGenerated(address indexed requester, uint256 otp);

   
    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized: Only owner");
        _;
    }

    modifier onlyManager(string memory _managerPassword) {
         _managerPassword=string(abi.encodePacked(keccak256(abi.encodePacked(_managerPassword))));
        require(managers[msg.sender], "Not authorized: Only manager");
        require(
            keccak256(abi.encodePacked(_managerPassword)) == keccak256(abi.encodePacked(managerPasswordHash)),
            "Incorrect manager password"
        );
        _;
    }

    modifier customerOnly(uint256 _customerId, string memory _password) {
        require(customers[_customerId].age != 0, "Customer does not exist");
        require(
            customers[_customerId].passwordHash == keccak256(abi.encodePacked(_password)),
            "Incorrect password"
        );
        _;
    }

    // Constructor - Securely set manager password during deployment
    constructor(string memory _managerPassword) {
        owner = msg.sender;
        managerPasswordHash = string(abi.encodePacked(keccak256(abi.encodePacked(_managerPassword))));
        managers[msg.sender] = true; // Owner is the first manager
    }

   

    
    function addManager(address _manager, string memory _managerPassword,uint256 _otp) public onlyOwner {
        _managerPassword=string(abi.encodePacked(keccak256(abi.encodePacked(_managerPassword))));
        require(
            keccak256(abi.encodePacked(_managerPassword)) == keccak256(abi.encodePacked(managerPasswordHash)),
            "Incorrect manager password"
        );
        require(
            managerOTPs[msg.sender] == _otp,
            "Invalid OTP"
        );
        managers[_manager] = true;
    }

    
    function addCustomer(
        uint256 _customerId,
        string memory _geography,
        uint256 _creditScore,
        uint256 _age,
        uint256 _balance,
        bool _hasCrCard,
        uint256 _estimatedSalary,
        string memory _password,
        string memory _managerPassword
    ) public onlyManager(_managerPassword) {
        require(_age >= 18, "Customer must be 18 years or older");

        // Hash the password before storing
        bytes32 passwordHash = keccak256(abi.encodePacked(_password));

        customers[_customerId] = Customer({
            geography: _geography,
            creditScore: _creditScore,
            age: _age,
            balance: _balance,
            hasCrCard: _hasCrCard,
            estimatedSalary: _estimatedSalary,
            passwordHash: passwordHash
        });
        customerCount++;
    }

    
    function deleteCustomer(uint256 _customerId, string memory _managerPassword) public onlyManager(_managerPassword) {
        require(customers[_customerId].age != 0, "Customer does not exist");

        delete customers[_customerId];
        customerCount--;
    }

    
    function updateCustomer(
        uint256 _customerId,
        string memory _geography,
        uint256 _creditScore,
        uint256 _age,
        uint256 _balance,
        bool _hasCrCard,
        uint256 _estimatedSalary,
        string memory _password,
        string memory _managerPassword
    ) public onlyManager(_managerPassword) {
        require(customers[_customerId].age != 0, "Customer does not exist");

        // Update with hashed password
        bytes32 passwordHash = keccak256(abi.encodePacked(_password));

        customers[_customerId] = Customer({
            geography: _geography,
            creditScore: _creditScore,
            age: _age,
            balance: _balance,
            hasCrCard: _hasCrCard,
            estimatedSalary: _estimatedSalary,
            passwordHash: passwordHash
        });
    }

    
    function viewCustomer(uint256 _customerId, string memory _managerPassword)
        public
        view
        onlyManager(_managerPassword)
        returns (Customer memory)
    {
        require(customers[_customerId].age != 0, "Customer does not exist");
        return customers[_customerId];
    }

    
    function checkCredentialsAndViewCustomer(uint256 _customerId, string memory _password)
        public
        view
        customerOnly(_customerId, _password)
        returns (Customer memory)
    {
        return customers[_customerId];
    }

    
    function changeManagerPassword(string memory _currentPassword, string memory _newPassword) public onlyOwner {
        _currentPassword=string(abi.encodePacked(keccak256(abi.encodePacked(_currentPassword))));
        require(
            keccak256(abi.encodePacked(_currentPassword)) == keccak256(abi.encodePacked(managerPasswordHash)),
            "Incorrect current password"
        );
        managerPasswordHash = string(abi.encodePacked(keccak256(abi.encodePacked(_newPassword))));
    }

    
    function generateCustomerOTP(uint256 _customerId, string memory _password)
        public
        customerOnly(_customerId, _password)
        returns (uint256)
    {
        uint256 otp = uint256(
            keccak256(abi.encodePacked(block.timestamp, msg.sender, _customerId))
        ) % 1000000; 
        customerOTPs[_customerId] = otp;
        emit OTPGenerated(msg.sender, otp);
        return otp;
    }

    
    function generateManagerOTP(string memory _managerPassword) public onlyManager(_managerPassword) returns (uint256) {
        uint256 otp = uint256(
            keccak256(abi.encodePacked(block.timestamp, msg.sender))
        ) % 1000000; // Generate 6-digit OTP
        managerOTPs[msg.sender] = otp;
        emit OTPGenerated(msg.sender, otp);
        return otp;
    }

    
    function viewCustomerWithOTP(uint256 _customerId, uint256 _otp) public view returns (Customer memory) {
        require(
            customerOTPs[_customerId] == _otp || managerOTPs[msg.sender] == _otp,
            "Invalid OTP"
        );
        return customers[_customerId];
    }

    
    function getCustomerCount() public view returns (uint256) {
        return customerCount;
    }
}
