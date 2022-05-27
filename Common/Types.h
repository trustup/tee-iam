#pragma once

#include <vector>
#include <string>
#include <map>


enum class OperationType:int 
{
	SIGNUP,
    SIGNIN,
    SIGNOUT,
    REMOVE,
    SERVICEACCESS
};



static OperationType get_optype_enum(std::string exchange_str){
    if (exchange_str == "signup") {
        return OperationType::SIGNUP;
    }else if (exchange_str == "signin") {
        return OperationType::SIGNIN;
    }else if (exchange_str == "signout"){
        return OperationType::SIGNOUT;
    }else if (exchange_str == "remove"){
        return OperationType::REMOVE;
    }else if (exchange_str == "serviceaccess"){
        return OperationType::SERVICEACCESS;
    }
}



static std::string get_exchange_name(OperationType op_type){
    switch(op_type){
        case OperationType::SIGNUP:     { return "signup";}
        case OperationType::SIGNIN:    { return "signin";}
        case OperationType::SIGNOUT:      { return "signout";}
        case OperationType::REMOVE:    { return "remove";}
        case OperationType::SERVICEACCESS:       { return "serviceaccess";}
    } 
}


inline bool replace(std::string &str, const std::string &from, const std::string &to)
{
    size_t start_pos = str.find(from);
    if (start_pos == std::string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}



inline std::vector<std::string> split(std::string stringToBeSplitted, std::string delimeter)
{
    std::vector<std::string> splittedString;
    unsigned int startIndex = 0;
    unsigned int endIndex = 0;
    while ((endIndex = stringToBeSplitted.find(delimeter, startIndex)) < stringToBeSplitted.size())
    {
        std::string val = stringToBeSplitted.substr(startIndex, endIndex - startIndex);
        splittedString.push_back(val);
        startIndex = endIndex + delimeter.size();
    }
    if (startIndex < stringToBeSplitted.size())
    {
        std::string val = stringToBeSplitted.substr(startIndex);
        splittedString.push_back(val);
    }
    return splittedString;
}