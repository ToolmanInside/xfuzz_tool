# xFuzz
## Quick Start
A container with the dependencies set up can be found [here](https://hub.docker.com/repository/docker/weizhang789/xfuzz_tool).
To open the container, install docker and run:
```
docker pull weizhang789/xfuzz_tool:v1 && docker run -it weizhang789/xfuzz_tool:v1 bash
```
To evaluate smart contracts in contracts/ inside the container, run:
```
python3 ./model_prediction/main.py && bash fuzzing_script
```
and you are done!

## Installation Instructions

### Solidity Compiler
```
sudo add-apt-repository ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install solc
```
### fuzzing engine
How to install fuzzing engine can refer [this](https://githubmemory.com/repo/duytai/sFuzz).
### static analysis tool
[slither](https://github.com/crytic/slither).

### Start fuzzing using the command:
```
python3 ./model_prediction/main.py && bash fuzzing_script
```
