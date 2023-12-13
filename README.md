# PyWarthog V0.1.2

## Description

PyWarthog is a Python project that does API call and others stuff to a local Warthog Node. Currently it can only be used with a local node.

## Installation

    ```bash pip install pywarthog ```	

## Usage

    ```python
    from warthog.pywarthog import Warthog

    warthog = Warthog('http://127.0.0.1:3000') 

    warthog.get_mempool()

    ```	

There is a lot of other functions but i've don't make a documentation yet. You can see the code to see what you can do with it.




