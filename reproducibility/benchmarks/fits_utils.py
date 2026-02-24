#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
import numpy as np
from astropy.io import fits
from datetime import datetime, timedelta, timezone

def _create_full_header(dimensions, filename):
    hdr = fits.Header()
    hdr['SIMPLE'] = (True, 'Conforms to the FITS standard')
    hdr['BITPIX'] = (-32, 'array data type')
    hdr['NAXIS'] = (2, 'number of array dimensions')
    hdr['NAXIS1'] = dimensions[1]
    hdr['NAXIS2'] = dimensions[0]
    
    now = datetime.now(timezone.utc)
    hdr['FILENAME'] = (filename, 'Original filename')
    hdr['DATE'] = (now.strftime('%Y-%m-%dT%H:%M:%S'), 'File creation date')
    hdr['TELESCOP'] = ('Sim_Telescope_1.5m', 'Telescope used')
    hdr['INSTRUME'] = ('SimCam_4K', 'Instrument used')
    hdr['EXPTIME'] = (random.uniform(30.0, 1200.0), '[s] Exposure time')
    
    hdr['CTYPE1'] = ('RA---TAN', 'Coordinate 1 projection')
    hdr['CTYPE2'] = ('DEC--TAN', 'Coordinate 2 projection')
    hdr['CRPIX1'] = (dimensions[1] / 2, 'Reference pixel 1')
    hdr['CRPIX2'] = (dimensions[0] / 2, 'Reference pixel 2')
    hdr['CRVAL1'] = (random.uniform(0, 360), '[deg] RA at ref pixel')
    hdr['CRVAL2'] = (random.uniform(-90, 90), '[deg] DEC at ref pixel')
    
    hdr['HISTORY'] = 'Test FITS file generated for GpuFitsCrypt benchmarks.'
    return hdr

def generate_fits_batch(num_images, output_path, size_category='mixed'):
    os.makedirs(output_path, exist_ok=True)
    
    standard_sizes = {
        'small': (2048, 2048),
        'medium': (7241, 7241),
        'large': (14200, 10650),
        'extra_large': (30000, 30000)
    }

    sizes_to_process = list(standard_sizes.keys()) if size_category == 'mixed' else [size_category]

    for cat in sizes_to_process:
        print(f"Generating {num_images} files for category: {cat}")
        dims = standard_sizes[cat]
        for i in range(num_images):
            fname = f'image_sim_{cat}_{str(i + 1).zfill(3)}.fits'
            full_path = os.path.join(output_path, fname)
            if os.path.exists(full_path): continue
            
            data = np.random.normal(loc=1500.0, scale=200.0, size=dims).astype(np.float32)
            header = _create_full_header(dims, fname)
            fits.writeto(full_path, data, header, overwrite=True)
    print("Data generation complete.")

if __name__ == "__main__":
    # Default behavior when run as script
    generate_fits_batch(1, "./fits_input_files", 'mixed')
