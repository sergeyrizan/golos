#include <steemit/blockchain_statistics/blockchain_statistics_api.hpp>

#include <steemit/application/impacted.hpp>
#include <steemit/chain/account_object.hpp>
#include <steemit/chain/comment_object.hpp>
#include <steemit/chain/history_object.hpp>

#include <steemit/chain/operation_notification.hpp>

#include "include/statistics_sender.hpp"


std::string increment_counter(std::string name);
std::string increment_counter(std::string name, uint32_t value);
std::string increment_counter(std::string name, fc::uint128_t value);
std::string increment_counter(std::string name, share_type value);

namespace steemit {
    namespace blockchain_statistics {

        using namespace steemit::protocol;

        struct blockchain_statistics_plugin::blockchain_statistics_plugin_impl {
        public:
            blockchain_statistics_plugin_impl(blockchain_statistics_plugin &plugin)
                    : _self(plugin) {
            }

            virtual ~blockchain_statistics_plugin_impl() {
            }

            void on_block(const signed_block &b);

            void pre_operation(const operation_notification &o);

            void post_operation(const operation_notification &o);

            blockchain_statistics_plugin &_self;
            flat_set<uint32_t> _tracked_buckets = {60, 3600, 21600, 86400,
                                                   604800, 2592000
            };
            flat_set<bucket_id_type> _current_buckets;
            uint32_t _maximum_history_per_bucket_size = 100;

            std::shared_ptr<stat_client> stat_sender;
        };

        struct operation_process {
            const blockchain_statistics_plugin &_plugin;
            const bucket_object &_bucket;
            chain::database &_db;
            std::shared_ptr<stat_client> stat_sender;

            operation_process(blockchain_statistics_plugin &bsp,
                const bucket_object &b, std::shared_ptr<stat_client> stat_sender)
                    : _plugin(bsp), _bucket(b), _db(bsp.database()), stat_sender(stat_sender) {
            }

            typedef void result_type;

            template<typename T>
            void operator()(const T &op) const {
            }

            void operator()(const transfer_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    b.transfers++;

                    if (op.amount.symbol == STEEM_SYMBOL) {
                        b.steem_transferred += op.amount.amount;

                        std::string tmp_s = increment_counter("steem_transferred", op.amount.amount);
                        stat_sender->push(tmp_s);
                    } else {
                        b.sbd_transferred += op.amount.amount;

                        std::string tmp_s = increment_counter("sbd_transferred", op.amount.amount);
                        stat_sender->push(tmp_s);
                    }
                });
                
            }

            void operator()(const interest_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    b.sbd_paid_as_interest += op.interest.amount;

                    std::string tmp_s = increment_counter("sbd_paid_as_interest", op.interest.amount);
                    stat_sender->push(tmp_s);
                });
            }

            void operator()(const account_create_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    b.paid_accounts_created++;

                    std::string tmp_s = increment_counter("paid_accounts_created");
                    stat_sender->push(tmp_s);
                });
            }

            void operator()(const pow_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    auto &worker = _db.get_account(op.worker_account);

                    if (worker.created == _db.head_block_time()) {
                        b.mined_accounts_created++;

                        std::string tmp_s = increment_counter("mined_accounts_created");
                        stat_sender->push(tmp_s);
                    }

                    b.total_pow++;

                    std::string tmp_s = increment_counter("total_pow");
                    stat_sender->push(tmp_s);

                    uint64_t bits =
                            (_db.get_dynamic_global_properties().num_pow_witnesses /
                             4) + 4;
                    uint128_t estimated_hashes = (1 << bits);
                    uint32_t delta_t;

                    if (b.seconds == 0) {
                        delta_t = _db.head_block_time().sec_since_epoch() -
                                  b.open.sec_since_epoch();
                    } else {
                        delta_t = b.seconds;
                    }

                    b.estimated_hashpower =
                            (b.estimated_hashpower * delta_t +
                             estimated_hashes) / delta_t;

                    tmp_s = increment_counter("estimated_hashpower", b.estimated_hashpower);
                    stat_sender->push(tmp_s);
                });
            }

            void operator()(const comment_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    auto &comment = _db.get_comment(op.author, op.permlink);

                    if (comment.created == _db.head_block_time()) {
                        if (comment.parent_author.length()) {
                            b.replies++;

                            std::string tmp_s = increment_counter("replies");
                            stat_sender->push(tmp_s);
                        } else {
                            b.root_comments++;

                            std::string tmp_s = increment_counter("root_comments");
                            stat_sender->push(tmp_s);
                        }
                    } else {
                        if (comment.parent_author.length()) {
                            b.reply_edits++;

                            std::string tmp_s = increment_counter("reply_edits");
                            stat_sender->push(tmp_s);
                        } else {
                            b.root_comment_edits++;

                            std::string tmp_s = increment_counter("root_comment_edits");
                            stat_sender->push(tmp_s);
                        }
                    }
                });
            }

            void operator()(const vote_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    const auto &cv_idx = _db.get_index<comment_vote_index>().indices().get<by_comment_voter>();
                    auto &comment = _db.get_comment(op.author, op.permlink);
                    auto &voter = _db.get_account(op.voter);
                    auto itr = cv_idx.find(boost::make_tuple(comment.id, voter.id));

                    if (itr->num_changes) {
                        if (comment.parent_author.size()) {
                            b.new_reply_votes++;

                            std::string tmp_s = increment_counter("new_reply_votes");
                            stat_sender->push(tmp_s);
                        } else {
                            b.new_root_votes++;

                            std::string tmp_s = increment_counter("new_root_votes");
                            stat_sender->push(tmp_s);
                        }
                    } else {
                        if (comment.parent_author.size()) {
                            b.changed_reply_votes++;

                            std::string tmp_s = increment_counter("changed_reply_votes");
                            stat_sender->push(tmp_s);
                        } else {
                            b.changed_root_votes++;

                            std::string tmp_s = increment_counter("changed_root_votes");
                            stat_sender->push(tmp_s);
                        }
                    }
                });
            }

            void operator()(const author_reward_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    b.payouts++;
                    b.sbd_paid_to_authors += op.sbd_payout.amount;
                    b.vests_paid_to_authors += op.vesting_payout.amount;

                    std::string tmp_s = increment_counter("payouts");
                    stat_sender->push(tmp_s);

                    tmp_s = increment_counter("sbd_paid_to_authors", op.sbd_payout.amount);
                    stat_sender->push(tmp_s);

                    tmp_s = increment_counter("vests_paid_to_authors", op.vesting_payout.amount);
                    stat_sender->push(tmp_s);
                });
            }

            void operator()(const curation_reward_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    b.vests_paid_to_curators += op.reward.amount;

                    std::string tmp_s = increment_counter("vests_paid_to_curators", op.reward.amount);
                    stat_sender->push(tmp_s);
                });
            }

            void operator()(const liquidity_reward_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    b.liquidity_rewards_paid += op.payout.amount;

                    std::string tmp_s = increment_counter("liquidity_rewards_paid", op.payout.amount);
                    stat_sender->push(tmp_s);
                });
            }

            void operator()(const transfer_to_vesting_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    b.transfers_to_vesting++;
                    b.steem_vested += op.amount.amount;

                    std::string tmp_s = increment_counter("transfers_to_vesting");
                    stat_sender->push(tmp_s);

                    tmp_s = increment_counter("steem_vested", op.amount.amount);
                    stat_sender->push(tmp_s);
                });
            }

            void operator()(const fill_vesting_withdraw_operation &op) const {
                auto &account = _db.get_account(op.from_account);

                _db.modify(_bucket, [&](bucket_object &b) {
                    b.vesting_withdrawals_processed++;

                    std::string tmp_s = increment_counter("vesting_withdrawals_processed");
                    stat_sender->push(tmp_s);

                    if (op.deposited.symbol == STEEM_SYMBOL) {
                        b.vests_withdrawn += op.withdrawn.amount;

                        tmp_s = increment_counter("vests_withdrawn", op.withdrawn.amount);
                        stat_sender->push(tmp_s);
                    } else {
                        b.vests_transferred += op.withdrawn.amount;

                        tmp_s = increment_counter("vests_transferred", op.withdrawn.amount);
                        stat_sender->push(tmp_s);
                    }

                    if (account.vesting_withdraw_rate.amount == 0) {
                        b.finished_vesting_withdrawals++;

                        tmp_s = increment_counter("finished_vesting_withdrawals");
                        stat_sender->push(tmp_s);
                    }
                });
            }

            void operator()(const limit_order_create_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    b.limit_orders_created++;

                    std::string tmp_s = increment_counter("limit_orders_created");
                    stat_sender->push(tmp_s);
                });
            }

            void operator()(const fill_order_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    b.limit_orders_filled += 2;

                    std::string tmp_s = increment_counter("limit_orders_filled", boost::numeric_cast<uint32_t>(2));
                    stat_sender->push(tmp_s);
                });
            }

            void operator()(const limit_order_cancel_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    b.limit_orders_cancelled++;

                    std::string tmp_s = increment_counter("limit_orders_cancelled");
                    stat_sender->push(tmp_s);
                });
            }

            void operator()(const convert_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    b.sbd_conversion_requests_created++;

                    std::string tmp_s = increment_counter("sbd_conversion_requests_created");
                    stat_sender->push(tmp_s);

                    b.sbd_to_be_converted += op.amount.amount;

                    tmp_s = increment_counter("sbd_to_be_converted", op.amount.amount);
                    stat_sender->push(tmp_s);
                });
            }

            void operator()(const fill_convert_request_operation &op) const {
                _db.modify(_bucket, [&](bucket_object &b) {
                    b.sbd_conversion_requests_filled++;
                    
                    std::string tmp_s = increment_counter("sbd_conversion_requests_filled");
                    stat_sender->push(tmp_s);

                    b.steem_converted += op.amount_out.amount;

                    tmp_s = increment_counter("steem_converted", op.amount_out.amount);
                    stat_sender->push(tmp_s);
                });
            }
        };

        void blockchain_statistics_plugin::blockchain_statistics_plugin_impl::on_block(const signed_block &b) {
            auto &db = _self.database();

            if (b.block_num() == 1) {
                db.create<bucket_object>([&](bucket_object &bo) {
                    bo.open = b.timestamp;
                    bo.seconds = 0;
                    bo.blocks = 1;
                });
            } else {
                db.modify(db.get(bucket_id_type()), [&](bucket_object &bo) {
                    bo.blocks++;
                });
            }

            _current_buckets.clear();
            _current_buckets.insert(bucket_id_type());

            const auto &bucket_idx = db.get_index<bucket_index>().indices().get<by_bucket>();

            uint32_t trx_size = 0;
            uint32_t num_trx = b.transactions.size();

            for (auto trx : b.transactions) {
                trx_size += fc::raw::pack_size(trx);
            }

            for (auto bucket : _tracked_buckets) {
                auto open = fc::time_point_sec(
                        (db.head_block_time().sec_since_epoch() / bucket) *
                        bucket);
                auto itr = bucket_idx.find(boost::make_tuple(bucket, open));

                if (itr == bucket_idx.end()) {
                    _current_buckets.insert(
                            db.create<bucket_object>([&](bucket_object &bo) {
                                bo.open = open;
                                bo.seconds = bucket;
                                bo.blocks = 1;
                            }).id);

                    if (_maximum_history_per_bucket_size > 0) {
                        try {
                            auto cutoff = fc::time_point_sec((
                                    safe<uint32_t>(db.head_block_time().sec_since_epoch()) -
                                    safe<uint32_t>(bucket) *
                                    safe<uint32_t>(_maximum_history_per_bucket_size)).value);

                            itr = bucket_idx.lower_bound(boost::make_tuple(bucket, fc::time_point_sec()));

                            while (itr->seconds == bucket &&
                                   itr->open < cutoff) {
                                auto old_itr = itr;
                                ++itr;
                                db.remove(*old_itr);
                            }
                        }
                        catch (fc::overflow_exception &e) {
                        }
                        catch (fc::underflow_exception &e) {
                        }
                    }
                } else {
                    db.modify(*itr, [&](bucket_object &bo) {
                        bo.blocks++;
                    });

                    _current_buckets.insert(itr->id);
                }

                db.modify(*itr, [&](bucket_object &bo) {
                    bo.transactions += num_trx;
                    bo.bandwidth += trx_size;
                });
            }
        }

        void blockchain_statistics_plugin::blockchain_statistics_plugin_impl::pre_operation(const operation_notification &o) {
            auto &db = _self.database();

            for (auto bucket_id : _current_buckets) {
                if (o.op.which() ==
                    operation::tag<delete_comment_operation>::value) {
                    delete_comment_operation op = o.op.get<delete_comment_operation>();
                    auto comment = db.get_comment(op.author, op.permlink);
                    const auto &bucket = db.get(bucket_id);

                    db.modify(bucket, [&](bucket_object &b) {
                        if (comment.parent_author.length()) {
                            b.replies_deleted++;
                        } else {
                            b.root_comments_deleted++;
                        }
                    });
                } else if (o.op.which() ==
                           operation::tag<withdraw_vesting_operation>::value) {
                    withdraw_vesting_operation op = o.op.get<withdraw_vesting_operation>();
                    auto &account = db.get_account(op.account);
                    const auto &bucket = db.get(bucket_id);

                    auto new_vesting_withdrawal_rate =
                            op.vesting_shares.amount /
                            STEEMIT_VESTING_WITHDRAW_INTERVALS;
                    if (op.vesting_shares.amount > 0 &&
                        new_vesting_withdrawal_rate == 0) {
                            new_vesting_withdrawal_rate = 1;
                    }

                    if (!db.has_hardfork(STEEMIT_HARDFORK_0_1)) {
                        new_vesting_withdrawal_rate *= 10000;
                    }

                    db.modify(bucket, [&](bucket_object &b) {
                        if (account.vesting_withdraw_rate.amount > 0) {
                            b.modified_vesting_withdrawal_requests++;
                        } else {
                            b.new_vesting_withdrawal_requests++;
                        }

                        // TODO: Figure out how to change delta when a vesting withdraw finishes. Have until March 24th 2018 to figure that out...
                        b.vesting_withdraw_rate_delta +=
                                new_vesting_withdrawal_rate -
                                account.vesting_withdraw_rate.amount;
                    });
                }
            }
        }
        void blockchain_statistics_plugin::blockchain_statistics_plugin_impl::post_operation(const operation_notification &o) {
            try {
                auto &db = _self.database();

                for (auto bucket_id : _current_buckets) {
                    const auto &bucket = db.get(bucket_id);

                    if (!is_virtual_operation(o.op)) {
                        db.modify(bucket, [&](bucket_object &b) {
                            b.operations++;
                        });
                    }
                    o.op.visit(operation_process(_self, bucket, stat_sender));
                }
            } FC_CAPTURE_AND_RETHROW()
        }
        blockchain_statistics_plugin::blockchain_statistics_plugin(application *app)
            : plugin(app), _my(new blockchain_statistics_plugin_impl(*this))  {
        }

        blockchain_statistics_plugin::~blockchain_statistics_plugin() {
            _my->stat_sender.reset();
            wlog("chain_stats plugin: stat_sender was shoutdowned");
        }

        void blockchain_statistics_plugin::plugin_set_program_options(
                boost::program_options::options_description &cli,
                boost::program_options::options_description &cfg
        ) {
            cli.add_options()
                    ("chain-stats-bucket-size", boost::program_options::value<string>()->default_value("[60,3600,21600,86400,604800,2592000]"),
                            "Track blockchain statistics by grouping orders into buckets of equal size measured in seconds specified as a JSON array of numbers")
                    ("chain-stats-history-per-bucket", boost::program_options::value<uint32_t>()->default_value(100),
                            "How far back in time to track history for each bucket size, measured in the number of buckets (default: 100)")
                    ("chain-stats-recipient-ip", boost::program_options::value<std::vector<std::string>>()->multitoken()->
                            zero_tokens()->composing(), "IP adresses of recipients");
            cfg.add(cli);
        }

        void blockchain_statistics_plugin::plugin_initialize(const boost::program_options::variables_map &options) {
            try {
                ilog("chain_stats_plugin: plugin_initialize() begin");

                uint32_t data_recipient_default_port;
                uint32_t stat_sender_sleeping_time;

                if (options.count("data_recipient_default_port")) {
                    data_recipient_default_port = options["data_recipient_default_port"].as<uint32_t>();
                }

                if (options.count("stat_sender_sleeping_time")) {
                    stat_sender_sleeping_time = options["stat_sender_sleeping_time"].as<uint32_t>();
                }

                _my->stat_sender = std::shared_ptr<stat_client>(new stat_client(data_recipient_default_port, stat_sender_sleeping_time));

                wlog("chain_stats plugin: stat_sender was initialized");

                chain::database &db = database();

                db.applied_block.connect([&](const signed_block &b) { _my->on_block(b); });
                db.pre_apply_operation.connect([&](const operation_notification &o) { _my->pre_operation(o); });
                db.post_apply_operation.connect([&](const operation_notification &o) { _my->post_operation(o); });

                db.add_plugin_index<bucket_index>();

                if (options.count("chain-stats-bucket-size")) {
                    const std::string &buckets = options["chain-stats-bucket-size"].as<string>();
                    _my->_tracked_buckets = fc::json::from_string(buckets).as<flat_set<uint32_t>>();
                }
                if (options.count("chain-stats-history-per-bucket")) {
                    _my->_maximum_history_per_bucket_size = options["chain-stats-history-per-bucket"].as<uint32_t>();
                }
                if (options.count("chain-stats-recipient-ip")) {
                    for (auto it: options["chain-stats-recipient-ip"].as<std::vector<std::string>>()) {
                        _my->stat_sender->add_address(it);
                    }
                }
                
                wlog("chain-stats-bucket-size: ${b}", ("b", _my->_tracked_buckets));
                wlog("chain-stats-history-per-bucket: ${h}", ("h", _my->_maximum_history_per_bucket_size));
                
                ilog("chain_stats_plugin: plugin_initialize() end");
            } FC_CAPTURE_AND_RETHROW()
        }

        void blockchain_statistics_plugin::plugin_startup() {
            ilog("chain_stats plugin: plugin_startup() begin");

            app().register_api_factory<blockchain_statistics_api>("chain_stats_api");

            if (_my->stat_sender->can_start()) {
                _my->stat_sender->start();
                wlog("chain_stats plugin: stat_sender was started");
                wlog("recipients endpoints: ${endpoints}", ( "endpoints", _my->stat_sender->get_endpoint_string_vector() ) );
            }
            else {
                wlog("chain_stats plugin: stat_sender was not started: no recipient's IPs were provided");
            }

            ilog("chain_stats plugin: plugin_startup() end");
        }

        const flat_set<uint32_t> &blockchain_statistics_plugin::get_tracked_buckets() const {
            return _my->_tracked_buckets;
        }

        uint32_t blockchain_statistics_plugin::get_max_history_per_bucket() const {
            return _my->_maximum_history_per_bucket_size;
        }

    }
} // steemit::blockchain_statistics

STEEMIT_DEFINE_PLUGIN(blockchain_statistics, steemit::blockchain_statistics::blockchain_statistics_plugin);

std::string increment_counter(std::string name) {
    std::string res = name + ":1|c";
    return res;
}

std::string increment_counter(std::string name, uint32_t value) {
    std::string res = name + ":";
    std::string num = std::to_string(value);
    res += num + "|c";

    return res;
}
std::string increment_counter(std::string name, fc::uint128_t value) {
    std::string res = name + ":";
    std::string num = std::string(value);
    res += num + "|c";

    return res;
}
std::string increment_counter(std::string name, share_type value) {
    std::string res = name + ":";
    std::string num = std::string(value);
    if (value < 0) {
        res += "-";    
    }
    res += num + "|c";
    return res;
}
