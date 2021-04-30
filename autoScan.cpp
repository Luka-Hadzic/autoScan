#include<string>
#include<vector>
#include <stdlib.h>
#include <fstream>
#include <thread>
#include <iostream>

typedef std::vector<std::string> stringVec;
typedef std::vector<int> numVec;

bool verbosity = false;
bool boutput = false;
bool defaultParams = true;

stringVec nmapScanSwitches
{
    "iL"/* Scan targets from a file */,
    "-sS"/* TCP SYN port scan */,
    "-sT"/* TCP connect port scan */,
    "-sU"/* UDP port scan */,
    "-sA"/* TCP ACK port scan */,
    "-sW"/* TCP Window port scan */,
    "-sM"/* TCP Maimon port scan */,
};

numVec defaultScanNumVec
{
    1,
    2,
    3
};

stringVec nmapPortSwitches
{
    "-p-"/* Port scan all ports */,
    "-F"/* Fast scan, first 100 */,
};

numVec defaultPortNumVec
{
    1
};

stringVec nmapServiceSwitches
{
    "-sV"/* tries to get version of service on ports */,
    "-O"/* Enables OS detection */,
    "-A"/* Enables OS detection, version detection, script scanning, and traceroute */
};

numVec defaultServiceNumVec
{
    0,
    1
};

stringVec digSwitches
{
    "ANY"/* find any record type */,
    "MX"/* find Mail eXchange type */,
    "txt"/* find TXT record */,
    "cname"/* find CNAME record */,
    "ns"/* find NS record */,
    "a"/* find A record */,
    "+trace"/* traces DNS path */
};

numVec defaultDigNumVec
{
    2,
    3,
    5
};

void startup()
{
    std::cout << "                                          tttt                              SSSSSSSSSSSSSSS                                                        " << std::endl;
    std::cout << "                                       ttt:::t                            SS:::::::::::::::S                                                       " << std::endl;
    std::cout << "                                       t:::::t                           S:::::SSSSSS::::::S                                                       " << std::endl;
    std::cout << "                                       t:::::t                           S:::::S     SSSSSSS                                                       " << std::endl;
    std::cout << "  aaaaaaaaaaaaa  uuuuuu    uuuuuuttttttt:::::ttttttt       ooooooooooo   S:::::S                cccccccccccccccc  aaaaaaaaaaaaa  nnnn  nnnnnnnn    " << std::endl;
    std::cout << "  a::::::::::::a u::::u    u::::ut:::::::::::::::::t     oo:::::::::::oo S:::::S              cc:::::::::::::::c  a::::::::::::a n:::nn::::::::nn  " << std::endl;
    std::cout << "  aaaaaaaaa:::::au::::u    u::::ut:::::::::::::::::t    o:::::::::::::::o S::::SSSS          c:::::::::::::::::c  aaaaaaaaa:::::an::::::::::::::nn " << std::endl;
    std::cout << "           a::::au::::u    u::::utttttt:::::::tttttt    o:::::ooooo:::::o  SS::::::SSSSS    c:::::::cccccc:::::c           a::::ann:::::::::::::::n" << std::endl;
    std::cout << "    aaaaaaa:::::au::::u    u::::u      t:::::t          o::::o     o::::o    SSS::::::::SS  c::::::c     ccccccc    aaaaaaa:::::a  n:::::nnnn:::::n" << std::endl;
    std::cout << "  aa::::::::::::au::::u    u::::u      t:::::t          o::::o     o::::o       SSSSSS::::S c:::::c               aa::::::::::::a  n::::n    n::::n" << std::endl;
    std::cout << " a::::aaaa::::::au::::u    u::::u      t:::::t          o::::o     o::::o            S:::::Sc:::::c              a::::aaaa::::::a  n::::n    n::::n" << std::endl;
    std::cout << "a::::a    a:::::au:::::uuuu:::::u      t:::::t    tttttto::::o     o::::o            S:::::Sc::::::c     ccccccca::::a    a:::::a  n::::n    n::::n" << std::endl;
    std::cout << "a::::a    a:::::au:::::::::::::::uu    t::::::tttt:::::to:::::ooooo:::::oSSSSSSS     S:::::Sc:::::::cccccc:::::ca::::a    a:::::a  n::::n    n::::n" << std::endl;
    std::cout << "a:::::aaaa::::::a u:::::::::::::::u    tt::::::::::::::to:::::::::::::::oS::::::SSSSSS:::::S c:::::::::::::::::ca:::::aaaa::::::a  n::::n    n::::n" << std::endl;
    std::cout << " a::::::::::aa:::a uu::::::::uu:::u      tt:::::::::::tt oo:::::::::::oo S:::::::::::::::SS   cc:::::::::::::::c a::::::::::aa:::a n::::n    n::::n" << std::endl;
    std::cout << "  aaaaaaaaaa  aaaa   uuuuuuuu  uuuu        ttttttttttt     ooooooooooo    SSSSSSSSSSSSSSS       cccccccccccccccc  aaaaaaaaaa  aaaa nnnnnn    nnnnnn" << std::endl;

    std::cout << "\n";
    std::cout << "\n";

    std::cout << "Thank you for choosing autoScan, the simple scanning tool\nVersion   :  alpha.0.1\nCodename  :  i_slipped_on_soap\nGithub    :  http...." << std::endl;
}

int mainText()
{
    int var;

    std::cout << "\n ----------------------------------------------------------" << std::endl;
    std::cout << "|  autoScan Main Menu                                      |\n|  [1]: Run full scan with default parameters              |\n|  [2]: Select which scans to run with default parameters  |\n|  [3]: Run full scan but manually set parameters          |\n|  [4]: Manually configure scans and parameters            |\n|  [5]: Configure autoScan settings                        |\n|                                                          |\n|  [9]: Exit autoScan                                      |\n";
    std::cout << " ----------------------------------------------------------" << std::endl;
    std::cin >> var;

    return var;
}

void settingsMenu(int caseVar)
{
    std::string input;
    switch (caseVar)
    {
    case 1:
        std::cout << "\nVerbosity is set to " << verbosity << ", would you like to set it to " << !verbosity << "?(y/n)\n" << std::endl;
        std::cin >> input;
        if (input == "y")
        {
            verbosity = !verbosity;
        }
        break;
    
    case 2:
        
        std::cout << "\nBash output is set to " << boutput << ", would you like to set it to " << !boutput << "?(y/n)\n" << std::endl;
        std::cin >> input;
        if (input == "y")
        {
            boutput = !boutput;
        }
        break;
    
    case 3:
        std::cout << "\nimplement this\n" << std::endl;
        break;
    
    case 9:
        std::cout << "\nExiting Settings Menu\n" << std::endl;
        break;
    
    default:
        std::cout << "\nInvalid Argument, Please Choose a Valid Option\n" << std::endl;
        break;
    }
}

void autoScanSettingsMenu()
{
    int var;
    while (var != 9)
    {
        std::cout << " ----------------------------" << std::endl;
        std::cout << "|  autoScan Settings Menu:   |" << std::endl;
        std::cout << "|  [1]: Set Verbosity        |\n|  [2]: Set Bash Output      |\n|  [3]: Manual/Tutorial      |\n|                            |\n|  [9]: Return to Main Menu  |\n";
        std::cout << " ----------------------------" << std::endl;

        std::cin >> var;
        settingsMenu(var);
    }
    
}

void nmapScan()
{
    if (defaultParams)
    {
        if (verbosity) // print out the thing
        {
            for (size_t i = 0; i < defaultScanNumVec.size(); i++)
            {
                std::cout << "nmap <target> " << nmapScanSwitches[defaultScanNumVec[i]] << std::endl;
            }
        }
        else // proceed w/o printing
        {
            for (size_t i = 0; i < defaultScanNumVec.size(); i++)
            {
                //std::cout << "nmap <target> " << nmapScanSwitches[defaultScanNumVec[i]] << std::endl;
            }
        }
         
    } else
    {
        /* code */
    }
}

void digScan()
{
    if (defaultParams)
    {
        /* code */
    } else
    {
        /* code */
    }
}

void niktoScan()
{
    if (defaultParams)
    {
        /* code */
    } else
    {
        /* code */
    }
}

void scanSetter(int nmap, int dig, int nikto)
{
    if (nmap == 1)
    {
        std::cout << "\nStarting nMap Scan..." << std::endl;
        nmapScan();
    }

    if (dig == 1)
    {
        std::cout << "\nStarting Dig Scan..." << std::endl;
        digScan();
    }

    if (nikto == 1)
    {
        std::cout << "\nStarting Nikto Scan..." << std::endl;
        niktoScan();
    }  
}

void mainMenu(int caseVar)
{
    std::cout << "" << std::endl;
    int x, y, z;

    switch (caseVar)
    {
    case 1:
        std::cout << "Beginning full scan with default parameters..." << std::endl;
        std::cout << "Results will be written to results.txt file..." << std::endl;
        std::cout << "results.txt wil be cleared on next startup..." << std::endl;
        scanSetter(1, 1, 1);
        break;
    
    case 2:
        std::cout << "Select which scans to run nMap[0(N)/1(Y)], Dig[0(N)/1(Y)], Nikto[0(N)/1(Y)]" << std::endl;
        std::cin >> x >> y >> z; //pass this to selector function
        scanSetter(x, y, z);
        break;
    
    case 3:
        defaultParams = false;
        std::cout << "hello" << std::endl;
        scanSetter(1, 1, 1);
        break;
    
    case 4:
        defaultParams = false;
        std::cout << "Select which scans to run nMap[0(N)/1(Y)], Dig[0(N)/1(Y)], Nikto[0(N)/1(Y)]" << std::endl;
        std::cin >> x >> y >> z;
        scanSetter(x, y, z);
        break;
    
    case 5:
        autoScanSettingsMenu();
        break;
    
    case 9:
        std::cout << "Exiting autoScan...\n" << std::endl;
        break;
    
    default:
        std::cout << "Invalid Argument, Please Choose a Valid Option" << std::endl;
        break;
    }
}

int main(int argc, char const *argv[])
{
    startup();
    int ans;
    while (ans != 9)
    {
        ans = mainText();
        mainMenu(ans);
    }
    
    return 0;
}

//nikto -h targetIP.txt
//https://www.youtube.com/watch?v=K78YOmbuT48