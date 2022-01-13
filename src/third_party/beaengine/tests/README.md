# unit tests

## requirements (debian/ubuntu)

```
apt install python-nose cmake python-yaml
```

## howto (debian/ubuntu)

```
cd ~
git clone https://github.com/BeaEngine/beaengine.git
cmake -DoptHAS_OPTIMIZED=TRUE -DoptHAS_SYMBOLS=TRUE -DoptBUILD_64BIT=FALSE -DoptBUILD_DLL=TRUE -DoptBUILD_LITE=FALSE beaengine
make
cp beaengine/lib/Linux.gnu.relwithdebinfo/libBeaEngine.so beaengine/headers
echo "export PYTHONPATH=$PYTHONPATH:$HOME/beaengine" >> $HOME/.bashrc
. ./~bashrc
cd beaengine & nosetests tests/*.py
```
