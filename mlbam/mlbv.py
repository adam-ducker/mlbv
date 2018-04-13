#!/usr/bin/env python
"""
This project provides a CLI interface into streaming MLB games from MLB.com

Links: http://statsapi.mlb.com/docs/

https://github.com/tonycpsu/mlbstreamer - a similar project

"""

import argparse
import logging
import os
import sys
import time

from datetime import datetime
from datetime import timedelta

import mlbam.config as config
import mlbam.gamedata as gamedata
import mlbam.standings as standings
import mlbam.stream as stream
import mlbam.util as util


LOG = None  # initialized in init_logging


HELP_HEADER = """MLB game tracker and stream viewer.
"""
HELP_FOOTER = """See README.md for full usage instructions and pre-requisites.

Feed Identifiers
You can use either the short form feed identifier or the long form:

    {}""".format(gamedata.get_feedtype_keystring())


def main(argv=None):

    # using argparse (2.7+) https://docs.python.org/2/library/argparse.html
    parser = argparse.ArgumentParser(description=HELP_HEADER, epilog=HELP_FOOTER,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-d", "--date", help="Display games/standings for date. Format: yyyy-mm-dd")
    parser.add_argument("-i", "--inning", help=("Start live/archive stream from inning. Format: {t|b}{inning_num}. "
                                                "t|b: (optional) top or bottom, inning_num: inning number. "
                                                "e.g.  '5' - start at 5th inning. 't5' start at top 5th. "
                                                "'b5' start at bottom 5th."))
    parser.add_argument("--inning-offset", type=int, metavar='secs',
                        help="Override the inning offset time in seconds. Default=240 (4 minutes)")
    parser.add_argument("--from-start", action="store_true", help="Start live/archive stream from beginning")
    parser.add_argument("--days", type=int, default=1, help="Number of days to display")
    parser.add_argument("--tomorrow", action="store_true", help="Use tomorrow's date")
    parser.add_argument("--yesterday", action="store_true", help="Use yesterday's date")
    parser.add_argument("-t", "--team", help="Play game for team, one of: {}".format(gamedata.TEAM_CODES))
    parser.add_argument("-f", "--feed",
                        help=("Feed type, either a live/archive game feed or highlight feed "
                              "(if available). Available feeds are shown in game list,"
                              "and have a short form and long form (see 'Feed identifiers' section below)"))
    parser.add_argument("--favs", help=("Favourite teams, a comma-separated list of favourite teams "
                                        "(normally specified in config file)"))
    parser.add_argument("--filter", action="store_true", help="Filter output for favourite teams only")
    parser.add_argument("-g", "--game", default='1', choices=('1', '2'),
                        help="Select game number of double-header")
    parser.add_argument("-r", "--resolution", choices=config.BANDWIDTH_CHOICES,
                        help="Stream resolution for streamlink (overrides settting in config file)")
    parser.add_argument("-s", "--scores", action="store_true",
                        help="Show scores (default off; overrides config file)")
    parser.add_argument("-n", "--no-scores", action="store_true",
                        help="Do not show scores (default on; overrides config file)")
    parser.add_argument("-l", "--linescore", action="store_true", help="Show linescores")
    parser.add_argument("--username", help="MLB.tv username. Required for live/archived games.")
    parser.add_argument("--password", help="MLB.tv password. Required for live/archived games.")
    parser.add_argument("--fetch", "--record", action="store_true", help="Save stream to file instead of playing")
    parser.add_argument("--wait", action="store_true",
                        help=("Wait for game to start (live games only). Will block launching the player until game time. "
                              "Useful when combined with the --fetch option."))
    parser.add_argument("--standings", nargs='?', const='division', metavar='CATEGORY',
                        help=("[CATEGORY] is one of: '" + ', '.join(standings.STANDINGS_OPTIONS) + "' [default: %(default)s]. "
                              "Display standings. This option will display selected standings category, then exit. "
                              "The standings category can be shortened down to one character (all matching "
                              "categories will be included), e.g. 'div'. "
                              "Can be combined with -d/--date option to show standings for any given date.")
                        )
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
    parser.add_argument("-D", "--debug", action="store_true", help="Turn on debug output")
    args = parser.parse_args()

    team_to_play = None
    feedtype = None

    # get our config
    config.CONFIG = config.MLBConfig()

    # append log files if DEBUG is set (from top of file)
    util.init_logging(os.path.join(config.CONFIG.dir,
                                   os.path.splitext(os.path.basename(sys.argv[0]))[0] + '.log'), True)

    mlb_gamedata = gamedata.GameData()

    global LOG
    LOG = logging.getLogger(__name__)

    if args.debug:
        config.CONFIG.parser['debug'] = 'true'
    if args.verbose:
        config.CONFIG.parser['verbose'] = 'true'
    if args.username:
        config.CONFIG.parser['username'] = args.username
    if args.password:
        config.CONFIG.parser['password'] = args.password
    if args.inning_offset:
        config.CONFIG.parser['stream_start_offset_secs'] = str(args.inning_offset)
    if args.team:
        team_to_play = args.team.lower()
        if team_to_play not in gamedata.TEAM_CODES:
            # Issue #4 all-star game has funky team codes
            LOG.warn('Unexpected team code: {}'.format(team_to_play))
    if args.feed:
        feedtype = gamedata.convert_to_long_feedtype(args.feed.lower())
    if args.resolution:
        config.CONFIG.parser['resolution'] = args.resolution
    if args.scores:
        config.CONFIG.parser['scores'] = 'true'
    elif args.no_scores:
        config.CONFIG.parser['scores'] = 'false'
    if args.linescore:
        config.CONFIG.parser['linescore'] = 'true'
    if args.favs:
        config.CONFIG.parser['favs'] = args.favs
    if args.filter:
        config.CONFIG.parser['filter'] = 'true'

    if args.yesterday:
        args.date = datetime.strftime(datetime.today() - timedelta(days=1), "%Y-%m-%d")
    elif args.tomorrow:
        args.date = datetime.strftime(datetime.today() + timedelta(days=1), "%Y-%m-%d")
    elif args.date is None:
        args.date = datetime.strftime(datetime.today(), "%Y-%m-%d")

    if args.standings:
        standings.get_standings(args.standings, args.date)
        return 0

    # fetch and display games (don't display if we're going to start a stream)
    game_data_list = mlb_gamedata.retrieve_and_display_game_data(args.date, args.days, team_to_play is None)

    if team_to_play is None:
        # nothing to play; we're done
        return 0

    # from this point we only care about first day in list
    if len(game_data_list) > 0:
        game_data = game_data_list[0]
    else:
        # nothing to stream
        return 0

    game_rec = stream.get_game_rec(game_data, team_to_play, args.game)

    if args.wait and not util.has_reached_time(game_rec['mlbdate']):
        LOG.info('Waiting for game to start. Local start time is %s', util.convert_time_to_local(game_rec['mlbdate']))
        print('Use Ctrl-c to quit .', end='', flush=True)
        count = 0
        while not util.has_reached_time(game_rec['mlbdate']):
            time.sleep(10)
            count += 1
            if count % 6 == 0:
                print('.', end='', flush=True)

        # refresh the game data
        LOG.info('Game time. Refreshing game data after wait...')
        game_data_list = mlb_gamedata.retrieve_and_display_game_data(args.date, 1, False)
        if len(game_data_list) > 0:
            game_data = game_data_list[0]
        else:
            LOG.error('Unexpected error: no game data found after refresh on wait')
            return 0

        game_rec = stream.get_game_rec(game_data, team_to_play, args.game)

    return stream.play_stream(game_rec, team_to_play, feedtype, args.date, args.fetch, args.from_start, args.inning)


if __name__ == "__main__" or __name__ == "main":
    sys.exit(main())

# vim: set filetype=python
