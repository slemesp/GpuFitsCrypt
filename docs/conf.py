import os
import sys

# Add python directory to path so autodoc can find gpufitscrypt
sys.path.insert(0, os.path.abspath('../python'))

# -- Project information -----------------------------------------------------
project = 'GpuFitsCrypt'
copyright = '2026, Samuel Lemes-Perera et al.'
author = 'Samuel Lemes-Perera'
release = '2.1.0'

# -- General configuration ---------------------------------------------------
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'myst_parser',
    'sphinx_copybutton',
]

source_suffix = {
    '.rst': 'restructuredtext',
    '.md': 'markdown',
}

master_doc = 'index'

# MyST Parser settings
myst_enable_extensions = [
    'colon_fence',
    'deflist',
    'fieldlist',
    'tasklist',
]
myst_heading_anchors = 3
suppress_warnings = ["myst.xref_missing"]

# Autodoc settings
autodoc_member_order = 'bysource'
autodoc_typehints = 'description'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------
html_theme = 'sphinx_rtd_theme'
html_theme_options = {
    'navigation_depth': 4,
    'collapse_navigation': False,
    'sticky_navigation': True,
    'includehidden': True,
    'titles_only': False,
}
