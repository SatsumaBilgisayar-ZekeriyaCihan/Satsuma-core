# -*- coding: utf-8 -*-
"""Satsuma Core — ortak dashboard widget kutuphanesi.

Paneller arasi tutarli gorunum icin tekrar kullanilabilir komponentler.
Tema (style.theme) uzerine kuruludur; mevcut acik SOC paletini korur.
"""
from .cards import MetricCard, SectionCard, StatusBadge, ActivityRow

__all__ = ['MetricCard', 'SectionCard', 'StatusBadge', 'ActivityRow']
