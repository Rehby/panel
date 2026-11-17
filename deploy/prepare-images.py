#!/usr/bin/python3
"""Prepare all catalog images; the panel keeps pull/build controls afterwards."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import images

if __name__=='__main__':
    images.install_images(Path(sys.argv[1]))
